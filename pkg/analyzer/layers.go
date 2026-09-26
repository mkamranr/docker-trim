package analyzer

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ImageReport is what a built image turned out to contain.
//
// Everything here is read by streaming the layer tarballs in process. docker-trim
// never shells out to skopeo, dive or docker for this: a size report that
// depends on tools the user may not have is a size report they cannot act on.
type ImageReport struct {
	Reference string `json:"reference"`
	// Source is "daemon" when the image was read from the local Docker engine
	// and "registry" when it was pulled straight from a registry.
	Source string `json:"source"`
	// TotalSize is the sum of every file in every layer, which is what the
	// image occupies on disk once pulled.
	TotalSize int64       `json:"totalSizeBytes"`
	Layers    []LayerInfo `json:"layers"`
	// Categories maps a bloat category to the bytes it accounts for.
	Categories map[string]int64 `json:"categories,omitempty"`
	// WastedBytes are bytes written in one layer and replaced in a later one.
	// They are still downloaded on every pull.
	WastedBytes int64 `json:"wastedBytes"`
	// WhiteoutBytes are bytes for files a later layer deleted. Deleting a file
	// in a later layer does not remove it from the image.
	WhiteoutBytes  int64  `json:"whiteoutBytes"`
	PackageManager string `json:"packageManager"`
	// OSID and OSVersionID come from /etc/os-release, e.g. "debian" and "12".
	// Vulnerability lookups need the exact release: a package version is only
	// vulnerable relative to the distribution that built it.
	OSID        string    `json:"osId,omitempty"`
	OSName      string    `json:"osName,omitempty"`
	OSVersionID string    `json:"osVersionId,omitempty"`
	Packages    []Package `json:"packages,omitempty"`
	// SetuidBinaries are files carrying the setuid or setgid bit, each a
	// standing privilege-escalation primitive.
	SetuidBinaries []string   `json:"setuidBinaries,omitempty"`
	TopFiles       []FileInfo `json:"topFiles,omitempty"`
	// User is the image's configured user; empty means root.
	User       string   `json:"user"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	// Notes record anything docker-trim could not determine, such as an unsupported
	// package database.
	Notes []string `json:"notes,omitempty"`
}

// LayerInfo is one layer's contribution.
type LayerInfo struct {
	Index   int    `json:"index"`
	DiffID  string `json:"diffId"`
	Size    int64  `json:"sizeBytes"`
	Files   int    `json:"files"`
	Command string `json:"command,omitempty"`
}

// FileInfo is one path in the image.
type FileInfo struct {
	Path  string `json:"path"`
	Size  int64  `json:"sizeBytes"`
	Layer int    `json:"layer"`
}

// Package is one installed package.
//
// An empty Ecosystem means an operating-system package, which keeps every
// existing construction site and test correct without change.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// SizeBytes is the installed size the package database reports, in bytes.
	SizeBytes int64 `json:"sizeBytes"`
	Essential bool  `json:"essential"`
	// Files are the paths the package owns. Populated only when the inspection
	// asked for ownership, which is what a trace needs to attribute a used file
	// back to the package that put it there.
	Files []string `json:"-"`
	// Ecosystem is the OSV ecosystem this package belongs to: "PyPI", "npm",
	// or empty for an operating-system package, whose ecosystem is a property
	// of the image rather than the package.
	Ecosystem string `json:"ecosystem,omitempty"`
	// Root is the directory a language package was installed into, such as
	// /app/node_modules or /usr/local/lib/python3.12/site-packages.
	//
	// It is what separates the application's own dependencies from the ones
	// its base image happens to carry. A node:22-alpine image ships 233 npm
	// packages inside npm itself; an app that installed three would otherwise
	// be told it has 238, which is true and useless.
	Root string `json:"root,omitempty"`
}

// IsOS reports whether this is an operating-system package.
//
// Only these can be reasoned about for removal: docker-trim edits Dockerfiles, and a
// Python or npm package arrives through requirements.txt or a lockfile, not
// through a line docker-trim can rewrite.
func (p Package) IsOS() bool { return p.Ecosystem == "" }

// bloatCategories classify a path by why it did not need to ship. Order
// matters: the first match wins, so the more specific prefixes come first.
var bloatCategories = []struct {
	name    string
	match   func(string) bool
	explain string
}{
	{"apt cache", prefixAny("/var/lib/apt/lists/", "/var/cache/apt/", "/var/cache/debconf/"),
		"apt's package index, rebuilt by any `apt-get update`"},
	{"pip cache", containsAny("/.cache/pip/"), "pip's wheel download cache"},
	{"npm cache", containsAny("/.npm/", "/.yarn/cache/", "/.pnpm-store/"), "npm's download cache"},
	{"go module cache", prefixAny("/go/pkg/mod/", "/root/.cache/go-build/"), "the Go module and build cache"},
	{"cargo registry", containsAny("/.cargo/registry/", "/.cargo/git/"), "cargo's crate registry"},
	{"maven repository", containsAny("/.m2/repository/"), "the local Maven repository"},
	{"apk cache", prefixAny("/var/cache/apk/"), "apk's package index"},
	{"python bytecode", isPyCache, "compiled bytecode, regenerated on demand"},
	{"documentation", prefixAny("/usr/share/doc/", "/usr/share/man/", "/usr/share/info/", "/usr/share/groff/"),
		"manual pages and package documentation"},
	{"locales", prefixAny("/usr/share/locale/", "/usr/share/i18n/"), "translations for languages the service does not use"},
	{"compiler toolchain", isToolchain, "compilers, headers and static libraries needed only to build"},
	{"temporary files", prefixAny("/tmp/", "/var/tmp/"), "scratch files a build step left behind"},
	{"source maps", suffixAny(".map"), "JavaScript source maps, useful in a browser and not in production"},
	{"test fixtures", containsAny("/test/", "/tests/", "/__tests__/", "/spec/"), "test code shipped with a dependency"},
}

func prefixAny(prefixes ...string) func(string) bool {
	return func(p string) bool {
		for _, pre := range prefixes {
			if strings.HasPrefix(p, pre) {
				return true
			}
		}
		return false
	}
}

func containsAny(subs ...string) func(string) bool {
	return func(p string) bool {
		for _, s := range subs {
			if strings.Contains(p, s) {
				return true
			}
		}
		return false
	}
}

func suffixAny(sufs ...string) func(string) bool {
	return func(p string) bool {
		for _, s := range sufs {
			if strings.HasSuffix(p, s) {
				return true
			}
		}
		return false
	}
}

func isPyCache(p string) bool {
	return strings.Contains(p, "/__pycache__/") || strings.HasSuffix(p, ".pyc") || strings.HasSuffix(p, ".pyo")
}

func isToolchain(p string) bool {
	switch {
	case strings.HasPrefix(p, "/usr/include/"),
		strings.HasPrefix(p, "/usr/lib/gcc/"),
		strings.HasPrefix(p, "/usr/libexec/gcc/"),
		strings.HasPrefix(p, "/usr/local/go/"):
		return true
	case strings.HasSuffix(p, ".a"), strings.HasSuffix(p, ".o"):
		return true
	}
	base := path.Base(p)
	for _, tool := range []string{"gcc", "g++", "cc1", "cc1plus", "ld", "as", "make", "cmake", "ar", "ranlib"} {
		if base == tool || strings.HasPrefix(base, tool+"-") {
			return true
		}
	}
	return false
}

// InspectImage reads an image and reports what it contains.
//
// The local Docker engine is tried first, so `docker-trim --image myapp:latest`
// works on an image that was just built and never pushed. A reference the
// daemon does not have is fetched from its registry instead.
func InspectImage(ctx context.Context, ref string) (*ImageReport, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("cannot parse image reference %q: %w", ref, err)
	}

	source := "daemon"
	img, err := daemon.Image(parsed, daemon.WithContext(ctx))
	if err != nil {
		var remoteErr error
		img, remoteErr = remote.Image(parsed,
			remote.WithContext(ctx),
			remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if remoteErr != nil {
			return nil, fmt.Errorf("cannot read %s from the Docker daemon (%v) or its registry: %w",
				ref, err, remoteErr)
		}
		source = "registry"
	}
	return inspect(ctx, ref, source, img, false)
}

// InspectImageWithOwnership is InspectImage plus the package file lists, which
// is what turns a trace into "these packages were never touched". It reads more
// of the image, so it is a separate entry point rather than the default.
func InspectImageWithOwnership(ctx context.Context, ref string) (*ImageReport, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("cannot parse image reference %q: %w", ref, err)
	}
	source := "daemon"
	img, err := daemon.Image(parsed, daemon.WithContext(ctx))
	if err != nil {
		var remoteErr error
		img, remoteErr = remote.Image(parsed,
			remote.WithContext(ctx),
			remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if remoteErr != nil {
			return nil, fmt.Errorf("cannot read %s from the Docker daemon (%v) or its registry: %w",
				ref, err, remoteErr)
		}
		source = "registry"
	}
	return inspect(ctx, ref, source, img, true)
}

// fileRecord tracks where a path was last written, so a path written twice can
// be charged as waste.
type fileRecord struct {
	layer int
	size  int64
}

func inspect(ctx context.Context, ref, source string, img v1.Image, withFiles bool) (*ImageReport, error) {
	rep := &ImageReport{Reference: ref, Source: source, Categories: map[string]int64{}}

	if cf, err := img.ConfigFile(); err == nil {
		rep.User = cf.Config.User
		rep.Entrypoint = cf.Config.Entrypoint
		rep.Cmd = cf.Config.Cmd
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("cannot list layers of %s: %w", ref, err)
	}

	var (
		seen     = make(map[string]fileRecord, 1<<14)
		pkgFiles = newPackageDB(withFiles)
		all      []FileInfo
	)

	for i, layer := range layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info := LayerInfo{Index: i}
		if d, err := layer.DiffID(); err == nil {
			info.DiffID = d.String()
		}

		rc, err := layer.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("cannot read layer %d of %s: %w", i, ref, err)
		}
		tr := tar.NewReader(rc)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				_ = rc.Close()
				return nil, fmt.Errorf("cannot read layer %d of %s: %w", i, ref, err)
			}
			if hdr.Typeflag == tar.TypeDir {
				continue
			}

			p := "/" + strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
			base := path.Base(p)

			// An overlay whiteout marks a deletion. The bytes it hides were
			// still shipped in the earlier layer.
			if strings.HasPrefix(base, ".wh.") {
				hidden := path.Join(path.Dir(p), strings.TrimPrefix(base, ".wh."))
				if prev, ok := seen[hidden]; ok {
					rep.WhiteoutBytes += prev.size
					delete(seen, hidden)
				}
				continue
			}

			info.Files++
			info.Size += hdr.Size

			if prev, ok := seen[p]; ok {
				// Written again in a later layer: the earlier copy is dead
				// weight that every pull still downloads.
				rep.WastedBytes += prev.size
			}
			seen[p] = fileRecord{layer: i, size: hdr.Size}

			if hdr.FileInfo().Mode()&(1<<11|1<<10) != 0 { // setuid, setgid
				rep.SetuidBinaries = append(rep.SetuidBinaries, p)
			}

			all = append(all, FileInfo{Path: p, Size: hdr.Size, Layer: i})
			pkgFiles.maybeCapture(p, tr)
		}
		_ = rc.Close()
		rep.Layers = append(rep.Layers, info)
	}

	for p, rec := range seen {
		rep.TotalSize += rec.size
		for _, c := range bloatCategories {
			if c.match(p) {
				rep.Categories[c.name] += rec.size
				break
			}
		}
	}

	rep.PackageManager, rep.Packages, rep.Notes = pkgFiles.parse()
	rep.OSID, rep.OSName, rep.OSVersionID = pkgFiles.osRelease()

	sort.Slice(all, func(i, j int) bool { return all[i].Size > all[j].Size })
	if len(all) > 20 {
		all = all[:20]
	}
	rep.TopFiles = all
	sort.Strings(rep.SetuidBinaries)
	return rep, nil
}

// BloatExplanation returns the human-readable reason a category is waste.
func BloatExplanation(category string) string {
	for _, c := range bloatCategories {
		if c.name == category {
			return c.explain
		}
	}
	return ""
}
