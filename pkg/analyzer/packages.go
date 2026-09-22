package analyzer

import (
	"bufio"
	"bytes"
	"io"
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
}

const (
	dpkgStatusPath = "/var/lib/dpkg/status"
	apkDBPath      = "/lib/apk/db/installed"
	// maxDBBytes caps how much of a package database is read into memory. A
	// dpkg status file for a full desktop install is around 3MB.
	maxDBBytes = 64 << 20
)

func newPackageDB() *packageDB { return &packageDB{} }

// maybeCapture reads the file body when the path is a package database. A
// later layer's copy wins, which matches how the image resolves the path.
func (d *packageDB) maybeCapture(p string, r io.Reader) {
	switch {
	case p == dpkgStatusPath:
		d.dpkgStatus = readCapped(r)
	case p == apkDBPath:
		d.apkDB = readCapped(r)
	case strings.HasPrefix(p, "/var/lib/rpm/"):
		d.sawRPM = true
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
		return "dpkg", parseDpkgStatus(d.dpkgStatus), nil
	case len(d.apkDB) > 0:
		return "apk", parseApkInstalled(d.apkDB), nil
	case d.sawRPM:
		return "rpm", nil, []string{
			"This image uses rpm, whose database dtrim cannot read yet, so no package " +
				"inventory is available. Size and layer analysis are unaffected."}
	}
	return "none", nil, nil
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
			if value == "required" || value == "important" {
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
