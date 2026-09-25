package analyzer

import (
	"bufio"
	"bytes"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

// packageDB captures the package databases as the layer tars stream past, so
// the inventory costs one pass over the image rather than a second one.
//
// dpkg and apk are parsed directly. rpm stores its database in Berkeley DB or
// sqlite, neither of which is worth carrying a dependency for in this release;
// it is detected and reported as unsupported instead of guessed at. See the
// CHANGELOG's known limitations.
type packageDB struct {
	dpkgStatus []byte
	apkDB      []byte
	sawRPM     bool
	// dpkgFiles maps a package name to the file list dpkg recorded for it.
	// Only collected when ownership is wanted, because a full Debian image has
	// hundreds of these and they are useless without a trace to compare against.
	dpkgFiles map[string][]byte
	// wantFiles turns that collection on.
	wantFiles bool
	// release is /etc/os-release, which names the distribution and version.
	release []byte
}

const (
	dpkgStatusPath = "/var/lib/dpkg/status"
	apkDBPath      = "/lib/apk/db/installed"
	dpkgInfoDir    = "/var/lib/dpkg/info/"
	osReleasePath  = "/etc/os-release"
	// Debian and Alpine both ship the real file here and symlink /etc to it,
	// and a tar stream carries the symlink rather than following it.
	usrLibOSReleasePath = "/usr/lib/os-release"
	// maxDBBytes caps how much of a package database is read into memory. A
	// dpkg status file for a full desktop install is around 3MB.
	maxDBBytes = 64 << 20
)

func newPackageDB(wantFiles bool) *packageDB {
	d := &packageDB{wantFiles: wantFiles}
	if wantFiles {
		d.dpkgFiles = map[string][]byte{}
	}
	return d
}

// maybeCapture reads the file body when the path is a package database. A
// later layer's copy wins, which matches how the image resolves the path.
func (d *packageDB) maybeCapture(p string, r io.Reader) {
	switch {
	case p == dpkgStatusPath:
		d.dpkgStatus = readCapped(r)
	case p == apkDBPath:
		d.apkDB = readCapped(r)
	case p == osReleasePath || p == usrLibOSReleasePath:
		// A later layer's copy wins, which is how the image resolves it.
		if body := readCapped(r); len(body) > 0 {
			d.release = body
		}
	case strings.HasPrefix(p, "/var/lib/rpm/"):
		d.sawRPM = true
	case d.wantFiles && strings.HasPrefix(p, dpkgInfoDir) && strings.HasSuffix(p, ".list"):
		// The file is named <package>.list or <package>:<arch>.list.
		name := strings.TrimSuffix(strings.TrimPrefix(p, dpkgInfoDir), ".list")
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		if body := readCapped(r); len(body) > 0 {
			d.dpkgFiles[name] = body
		}
	}
}

func readCapped(r io.Reader) []byte {
	b, err := io.ReadAll(io.LimitReader(r, maxDBBytes))
	if err != nil {
		return nil
	}
	return b
}

func (d *packageDB) parse() (manager string, pkgs []Package, notes []string) {
	switch {
	case len(d.dpkgStatus) > 0:
		pkgs = parseDpkgStatus(d.dpkgStatus)
		if d.wantFiles {
			attachDpkgFiles(pkgs, d.dpkgFiles)
		}
		return "dpkg", pkgs, nil
	case len(d.apkDB) > 0:
		pkgs = parseApkInstalled(d.apkDB)
		if d.wantFiles {
			attachApkFiles(pkgs, d.apkDB)
		}
		return "apk", pkgs, nil
	case d.sawRPM:
		return "rpm", nil, []string{
			"This image uses rpm, whose database dtrim cannot read yet, so no package " +
				"inventory is available. Size and layer analysis are unaffected."}
	}
	return "none", nil, nil
}

// osRelease reads the distribution id, pretty name and version out of
// /etc/os-release.
func (d *packageDB) osRelease() (id, name, versionID string) {
	sc := bufio.NewScanner(bytes.NewReader(d.release))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"'`)
		switch key {
		case "ID":
			id = value
		case "PRETTY_NAME":
			name = value
		case "VERSION_ID":
			versionID = value
		}
	}
	return id, name, versionID
}

// parseDpkgStatus reads /var/lib/dpkg/status: RFC822-style stanzas separated by
// a blank line, one per package.
func parseDpkgStatus(b []byte) []Package {
	var (
		out  []Package
		cur  Package
		kept bool
	)
	flush := func() {
		if kept && cur.Name != "" {
			out = append(out, cur)
		}
		cur, kept = Package{}, false
	}

	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		// Continuation lines of a multi-line field start with a space.
		if strings.HasPrefix(line, " ") {
			continue
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch key {
		case "Package":
			cur.Name = value
		case "Version":
			cur.Version = value
		case "Installed-Size":
			// dpkg reports kibibytes.
			if kb, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
				cur.SizeBytes = kb * 1024
			}
		case "Essential":
			cur.Essential = value == "yes"
		case "Priority":
			// Only "required" means the system breaks without it. Debian's
			// "important" means "expected on a Unix-like system", which covers
			// vim-tiny, nano, less and procps: all perfectly removable from a
			// container, and treating them as untouchable would hide most of
			// what a trace is for. Note that libc6 is merely "optional", so
			// priority is never what protects the packages that matter; the
			// explicit list in usage.go does that.
			if value == "required" {
				cur.Essential = true
			}
		case "Status":
			// Only packages that are actually unpacked and configured are
			// present in the filesystem; removed-but-known ones are not.
			kept = strings.HasSuffix(value, " installed")
		}
	}
	flush()

	sort.Slice(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	return out
}

// parseApkInstalled reads /lib/apk/db/installed, whose records use one-letter
// field keys: P package, V version, I installed size in bytes.
func parseApkInstalled(b []byte) []Package {
	var (
		out []Package
		cur Package
	)
	flush := func() {
		if cur.Name != "" {
			out = append(out, cur)
		}
		cur = Package{}
	}

	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		key, value := line[0], line[2:]
		switch key {
		case 'P':
			cur.Name = value
		case 'V':
			cur.Version = value
		case 'I':
			if n, err := strconv.ParseInt(value, 10, 64); err == nil {
				cur.SizeBytes = n
			}
		}
	}
	flush()

	// alpine-baselayout, busybox and musl are what makes the image bootable.
	for i := range out {
		switch out[i].Name {
		case "musl", "busybox", "alpine-baselayout", "alpine-keys", "apk-tools", "ca-certificates-bundle":
			out[i].Essential = true
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SizeBytes > out[j].SizeBytes })
	return out
}

// attachDpkgFiles records which paths each package owns.
func attachDpkgFiles(pkgs []Package, lists map[string][]byte) {
	for i := range pkgs {
		body, ok := lists[pkgs[i].Name]
		if !ok {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			// Directories are listed alongside files and are owned by many
			// packages at once, so they say nothing about who is in use.
			if line := sc.Text(); strings.HasPrefix(line, "/") && !strings.HasSuffix(line, "/") {
				pkgs[i].Files = append(pkgs[i].Files, line)
			}
		}
	}
}

// attachApkFiles walks the apk database a second time for its path records.
//
// apk stores a path as a directory line (F:) followed by the names in it (R:),
// so the full path has to be reassembled as the file is read.
func attachApkFiles(pkgs []Package, db []byte) {
	byName := make(map[string]*Package, len(pkgs))
	for i := range pkgs {
		byName[pkgs[i].Name] = &pkgs[i]
	}

	var (
		cur *Package
		dir string
	)
	sc := bufio.NewScanner(bytes.NewReader(db))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch key, value := line[0], line[2:]; key {
		case 'P':
			cur, dir = byName[value], ""
		case 'F':
			dir = value
		case 'R':
			if cur != nil {
				cur.Files = append(cur.Files, "/"+path.Join(dir, value))
			}
		}
	}
}
