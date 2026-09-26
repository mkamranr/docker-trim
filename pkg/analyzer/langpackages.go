package analyzer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

// Language package inventory: PyPI and npm.
//
// These matter more than the operating-system packages they sit beside. A slim
// base image's CVEs are usually low severity and unreachable; the exploitable
// ones tend to live in the application's own dependency tree. Scanning only the
// OS half and reporting a number invites exactly the wrong conclusion.
//
// Both are read from what the image actually contains rather than from a
// manifest in the build context, because the two differ: a lockfile says what
// was meant to be installed, and site-packages says what is there.

// The OSV ecosystem names, verified against api.osv.dev.
const (
	EcosystemPyPI = "PyPI"
	EcosystemNpm  = "npm"
)

// Caps on the language inventory.
//
// The OS databases are a handful of files; this is potentially thousands, and a
// real node_modules on this machine holds 837 package.json files across 34
// nested trees. Without a budget, a pathological image would be read entirely
// into memory.
const (
	maxLangPackages = 4000
	maxLangBytes    = 32 << 20
)

// distInfoDir matches a Python distribution directory, which encodes the
// package name and version but is not authoritative about either: METADATA is,
// because it carries the name with its original spelling and any epoch.
var distInfoDir = regexp.MustCompile(`^(.+?)-([^-]+)\.(dist-info|egg-info)$`)

// pep503 normalises a Python package name: lowercase, with runs of -_. folded
// to a single dash.
//
// OSV normalises names itself, so this is not needed for the lookup. It is
// needed for our own deduplication: without it Jinja2 and jinja2 are counted as
// two packages in the same image.
var pep503 = regexp.MustCompile(`[-_.]+`)

func normalisePyPI(name string) string {
	return pep503.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
}

// langPackage is one package found in the image, before deduplication.
type langPackage struct {
	name, version, ecosystem string
	root                     string
	size                     int64
}

// captureLanguage records a language package if the path is one.
//
// It reports whether it consumed the entry, since the caller shares one tar
// reader and a handler must read the body there or not at all.
func (d *packageDB) captureLanguage(p string, r readerFunc) bool {
	switch {
	case isPythonMetadata(p):
		body := d.budgetedRead(r)
		if body == nil {
			return true
		}
		if name, version := parsePythonMetadata(body); name != "" && version != "" {
			d.addLang(langPackage{
				name: normalisePyPI(name), version: version, ecosystem: EcosystemPyPI,
				root: installRoot(p, "site-packages", "dist-packages"),
			})
		}
		return true

	case isNpmManifest(p):
		body := d.budgetedRead(r)
		if body == nil {
			return true
		}
		if name, version := parseNpmManifest(body); name != "" && version != "" {
			d.addLang(langPackage{
				name: name, version: version, ecosystem: EcosystemNpm,
				root: installRoot(p, "node_modules"),
			})
		}
		return true
	}
	return false
}

// isPythonMetadata matches the metadata file of an installed distribution.
//
// The directory has to end in .dist-info or .egg-info, which is what separates
// an installed package from a source tree that merely contains a file of the
// same name.
func isPythonMetadata(p string) bool {
	base := path.Base(p)
	if base != "METADATA" && base != "PKG-INFO" {
		return false
	}
	dir := path.Base(path.Dir(p))
	return distInfoDir.MatchString(dir)
}

// isNpmManifest matches a package.json that is the root of an installed
// package.
//
// Matching on the shape of the path rather than the filename is what keeps a
// package.json inside a test fixture or an example directory out of the
// inventory. Nesting is handled naturally: node_modules/a/node_modules/b is
// just as valid as node_modules/b.
func isNpmManifest(p string) bool {
	if path.Base(p) != "package.json" {
		return false
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 3 {
		return false
	}
	// .../node_modules/<name>/package.json
	if parts[len(parts)-3] == "node_modules" {
		return true
	}
	// .../node_modules/@<scope>/<name>/package.json
	if len(parts) >= 4 && parts[len(parts)-4] == "node_modules" &&
		strings.HasPrefix(parts[len(parts)-3], "@") {
		return true
	}
	return false
}

// parsePythonMetadata reads Name and Version out of a METADATA or PKG-INFO
// file, which is RFC 822 shaped: headers first, then a blank line and the long
// description. Only the headers are read, and the description can be large.
func parsePythonMetadata(body []byte) (name, version string) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch key {
		case "Name":
			name = strings.TrimSpace(value)
		case "Version":
			version = strings.TrimSpace(value)
		}
		if name != "" && version != "" {
			return name, version
		}
	}
	return name, version
}

// parseNpmManifest reads the name and version from a package.json.
//
// A package.json with no version is a workspace root or a private stub rather
// than an installed package, and nothing can be looked up without one.
func parseNpmManifest(body []byte) (name, version string) {
	var manifest struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return "", ""
	}
	return strings.TrimSpace(manifest.Name), strings.TrimSpace(manifest.Version)
}

// installRoot returns the path up to and including the outermost of the given
// directory names.
//
// The outermost is deliberate: a package nested inside another package's
// node_modules belongs to whichever tree contains them both, which is the tree
// the user installed.
func installRoot(p string, names ...string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, part := range parts {
		for _, name := range names {
			if part == name {
				return "/" + strings.Join(parts[:i+1], "/")
			}
		}
	}
	return ""
}

// addLang records a package, deduplicated by ecosystem, name and version.
//
// Nested node_modules install the same package many times over, so without
// this an image would report several hundred copies of the same dependency and
// query OSV for each.
func (d *packageDB) addLang(p langPackage) {
	if len(d.langPackages) >= maxLangPackages {
		d.langTruncated = true
		return
	}
	key := p.ecosystem + "\x00" + p.name + "\x00" + p.version
	if idx, ok := d.langIndex[key]; ok {
		// The same package can appear in several trees. Keep the shallowest
		// root, which is the one the user installed rather than a copy vendored
		// inside another dependency.
		if existing := d.langPackages[idx]; p.root != "" &&
			(existing.root == "" || len(p.root) < len(existing.root)) {
			d.langPackages[idx].root = p.root
		}
		return
	}
	if d.langIndex == nil {
		d.langIndex = map[string]int{}
	}
	d.langIndex[key] = len(d.langPackages)
	d.langPackages = append(d.langPackages, p)
}

// langPackagesAsPackages converts the inventory to the shared type.
func (d *packageDB) languagePackages() []Package {
	out := make([]Package, 0, len(d.langPackages))
	for _, p := range d.langPackages {
		out = append(out, Package{
			Name: p.name, Version: p.version, Ecosystem: p.ecosystem,
			SizeBytes: p.size, Root: p.root,
		})
	}
	return out
}
