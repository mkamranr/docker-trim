package analyzer

import (
	"os"
	"strings"
	"testing"
)

// The fixture is three real headers taken from redhat/ubi9-minimal, written
// with a 512-byte page so that every one of them spans an overflow chain --
// the case a 4096-byte page would not exercise for packages this small.
//
// The expected values are what `rpm -qa` reports for the same three packages,
// not what this parser produced. Between them they cover a package with no
// epoch and no files to speak of, an ordinary one, and one whose epoch has to
// appear in the version because it changes which advisory applies.
const rpmFixture = "testdata/rpmdb.sqlite"

func TestParseRPMDB(t *testing.T) {
	data, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseRPMDB(data, true)
	if err != nil {
		t.Fatalf("parseRPMDB: %v", err)
	}

	want := []struct {
		name    string
		version string
		size    int64
	}{
		{"basesystem", "11-13.el9", 0},
		{"bzip2-libs", "1.0.8-11.el9", 78116},
		{"gdbm-libs", "1:1.23-1.el9", 128586},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for i, w := range want {
		got := pkgs[i]
		if got.Name != w.name || got.Version != w.version || got.SizeBytes != w.size {
			t.Errorf("package %d = %q %q %d, want %q %q %d",
				i, got.Name, got.Version, got.SizeBytes, w.name, w.version, w.size)
		}
		if !got.IsOS() {
			t.Errorf("%s: rpm packages are operating-system packages", got.Name)
		}
	}
}

// TestParseRPMDBFiles checks the directory/basename tables are recombined into
// absolute paths, which is what a trace needs to attribute a used file back to
// the package that installed it.
func TestParseRPMDBFiles(t *testing.T) {
	data, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := parseRPMDB(data, true)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range pkgs {
		for _, f := range p.Files {
			if !strings.HasPrefix(f, "/") {
				t.Errorf("%s owns %q, which is not an absolute path", p.Name, f)
			}
			found = true
		}
	}
	if !found {
		t.Error("no package reported any files; the dirname/basename join is not working")
	}

	// And that asking for no files really costs nothing.
	pkgs, err = parseRPMDB(data, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if len(p.Files) != 0 {
			t.Errorf("%s: files collected despite wantFiles being false", p.Name)
		}
	}
}

// TestParseRPMDBRejectsRatherThanEmpties is the honesty property. An
// unreadable database has to be an error: returning no packages would be
// indistinguishable from an image that genuinely has none, and would be
// reported as a clean image.
func TestParseRPMDBRejectsRatherThanEmpties(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"not sqlite", []byte("this is not a database at all, not even close")},
		{"header only", append([]byte(sqliteMagic), make([]byte, 84)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkgs, err := parseRPMDB(tc.data, false)
			if err == nil {
				t.Fatalf("got %d packages and no error, want an error", len(pkgs))
			}
			if pkgs != nil {
				t.Errorf("got packages alongside an error: %+v", pkgs)
			}
		})
	}
}

// TestParseRPMDBTruncated feeds every truncation of a real database through
// the parser. Page numbers, cell offsets and header offsets all come from the
// file being read, so each one is attacker-controlled if the image is; none of
// them may panic.
func TestParseRPMDBTruncated(t *testing.T) {
	data, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(data); n += 97 {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on the first %d bytes: %v", n, r)
				}
			}()
			_, _ = parseRPMDB(data[:n], true)
		}()
	}
}

// TestParseRPMDBCorrupted flips bytes in the header area, where the counts and
// offsets live, and requires the same of it.
func TestParseRPMDBCorrupted(t *testing.T) {
	orig, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(orig); i += 61 {
		data := make([]byte, len(orig))
		copy(data, orig)
		data[i] ^= 0xff
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic with byte %d flipped: %v", i, r)
				}
			}()
			_, _ = parseRPMDB(data, true)
		}()
	}
}

func TestParseRPMHeaderRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"too short", []byte{0, 0, 0}},
		{"absurd entry count", []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}},
		{"absurd store size", []byte{0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}},
		{"describes more than it holds", []byte{0, 0, 0, 4, 0, 0, 0, 16}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRPMHeader(tc.blob, true); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestOpenSQLiteRejects(t *testing.T) {
	bad := append([]byte(sqliteMagic), make([]byte, 84)...)
	bad[16], bad[17] = 0x00, 0x03 // 768: not a power of two
	if _, err := openSQLite(bad); err == nil {
		t.Error("a non-power-of-two page size should be rejected")
	}
	short := []byte("SQLite format 3\x00")
	if _, err := openSQLite(short); err == nil {
		t.Error("a file shorter than its header should be rejected")
	}
}

func TestUvarint(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x81, 0x00}, 128, 2},
		{[]byte{0x82, 0x21}, 289, 2},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0xffffffffffffffff, 9},
		{[]byte{0x81}, 0, 0}, // truncated
		{nil, 0, 0},
	} {
		got, n := uvarint(tc.in)
		if n != tc.n || (n > 0 && got != tc.want) {
			t.Errorf("uvarint(%x) = %d, %d; want %d, %d", tc.in, got, n, tc.want, tc.n)
		}
	}
}

// The tests above cover the parser. These cover the wiring: that the right
// paths are picked up out of the layer stream, and that each way of failing
// produces a note rather than a silently empty inventory.

func rpmPackageDB(t *testing.T, wal string) *packageDB {
	t.Helper()
	data, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	d := newPackageDB(true)
	d.maybeCapture(rpmDBPath, strings.NewReader(string(data)))
	if wal != "" {
		d.maybeCapture(rpmDBPath+"-wal", strings.NewReader(wal))
	}
	return d
}

func TestPackageDBReadsRPM(t *testing.T) {
	manager, pkgs, notes := rpmPackageDB(t, "").parse()
	if manager != "rpm" {
		t.Errorf("manager = %q, want rpm", manager)
	}
	if len(pkgs) != 3 {
		t.Errorf("packages = %d, want 3", len(pkgs))
	}
	if len(notes) != 0 {
		t.Errorf("notes = %q, want none for a database that read cleanly", notes)
	}
}

// A write-ahead log with anything in it means the database file alone may be
// out of date, and an inventory that might be stale has to say so.
func TestPackageDBNotesNonEmptyRPMWAL(t *testing.T) {
	_, pkgs, notes := rpmPackageDB(t, "not empty").parse()
	if len(pkgs) != 3 {
		t.Errorf("packages = %d, want the inventory to still be reported", len(pkgs))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "write-ahead log") {
		t.Errorf("notes = %q, want one naming the write-ahead log", notes)
	}
}

// Berkeley DB, as RHEL 8 and earlier use. Unsupported, and that must read as
// unsupported rather than as an image with no packages in it.
func TestPackageDBNotesBerkeleyDB(t *testing.T) {
	d := newPackageDB(false)
	d.maybeCapture("/var/lib/rpm/Packages", strings.NewReader("\x00\x06\x15\x61 not sqlite"))
	manager, pkgs, notes := d.parse()
	if manager != "rpm" {
		t.Errorf("manager = %q, want rpm", manager)
	}
	if len(pkgs) != 0 {
		t.Errorf("packages = %d, want none", len(pkgs))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "Berkeley DB") {
		t.Errorf("notes = %q, want one explaining the Berkeley DB format", notes)
	}
}

// An rpmdb.sqlite that cannot be parsed is the dangerous case: the manager is
// known, so nothing else signals a problem, and an empty package list would be
// read as an image with nothing installed.
func TestPackageDBNotesUnreadableRPM(t *testing.T) {
	d := newPackageDB(false)
	d.maybeCapture(rpmDBPath, strings.NewReader("SQLite format 3\x00 truncated right here"))
	manager, pkgs, notes := d.parse()
	if manager != "rpm" {
		t.Errorf("manager = %q, want rpm", manager)
	}
	if len(pkgs) != 0 {
		t.Errorf("packages = %d, want none", len(pkgs))
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "could not be read") {
		t.Errorf("notes = %q, want one saying the database could not be read", notes)
	}
}
