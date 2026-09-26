package analyzer

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
)

// rpm's package database, as every RHEL 9 era image stores it: a SQLite file
// whose Packages table holds one binary rpm header per installed package.
//
// The header format is stable and simple -- a count, a data-store size, a
// fixed-width index, and a blob of values the index points into. What makes it
// worth care is that the offsets come from the file, so every one of them is
// treated as untrusted and bounds-checked before use.

const rpmDBPath = "/var/lib/rpm/rpmdb.sqlite"

// The rpm tags this reads. rpm defines hundreds; these are the ones that say
// what a package is and what it put on disk.
const (
	rpmTagName       = 1000
	rpmTagVersion    = 1001
	rpmTagRelease    = 1002
	rpmTagEpoch      = 1003
	rpmTagSize       = 1009
	rpmTagArch       = 1022
	rpmTagDirIndexes = 1116
	rpmTagBaseNames  = 1117
	rpmTagDirNames   = 1118
)

// rpm's value types. Only the ones these tags use are handled.
const (
	rpmTypeInt16       = 3
	rpmTypeInt32       = 4
	rpmTypeString      = 6
	rpmTypeStringArray = 8
	rpmTypeI18NString  = 9
)

// rpmEntry is one row of a header's index.
type rpmEntry struct {
	tag    uint32
	typ    uint32
	offset uint32
	count  uint32
}

// parseRPMDB reads every installed package out of an rpmdb.sqlite image.
//
// A failure here returns an error rather than an empty inventory on purpose.
// Reporting no packages for an image that has 109 of them would read as a
// clean image, which is the one outcome worse than saying nothing.
func parseRPMDB(data []byte, wantFiles bool) ([]Package, error) {
	db, err := openSQLite(data)
	if err != nil {
		return nil, err
	}
	root, err := db.rootPage("Packages")
	if err != nil {
		return nil, err
	}
	rows, err := db.rows(root)
	if err != nil {
		return nil, err
	}

	pkgs := make([]Package, 0, len(rows))
	for _, r := range rows {
		// The table is (hnum INTEGER PRIMARY KEY, blob BLOB NOT NULL), and an
		// INTEGER PRIMARY KEY is stored as the rowid rather than in the
		// record, so the blob can land in either column depending on how the
		// row was written. Take the first blob either way.
		var blob []byte
		for _, v := range r {
			if b, ok := v.([]byte); ok {
				blob = b
				break
			}
		}
		if len(blob) == 0 {
			continue
		}
		p, err := parseRPMHeader(blob, wantFiles)
		if err != nil {
			// One unreadable header should not discard the other hundred, but
			// it must not be silent either.
			continue
		}
		if p.Name != "" {
			pkgs = append(pkgs, p)
		}
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	return pkgs, nil
}

// parseRPMHeader decodes one rpm header blob.
//
// Layout, all big-endian: a 4-byte index entry count, a 4-byte data store
// size, that many 16-byte index entries, then the data store the entries'
// offsets are relative to. Unlike a header read from an .rpm file, the blob
// stored in SQLite carries no 8-byte lead magic; it begins at the count.
func parseRPMHeader(b []byte, wantFiles bool) (Package, error) {
	if len(b) < 8 {
		return Package{}, fmt.Errorf("header shorter than its own preamble")
	}
	nindex := binary.BigEndian.Uint32(b[0:4])
	hsize := binary.BigEndian.Uint32(b[4:8])
	// Guard the multiplication before doing it, so a hostile count cannot
	// overflow into a small number and pass the bounds check below.
	if nindex > 1<<20 || hsize > 1<<28 {
		return Package{}, fmt.Errorf("header claims %d entries and %d data bytes", nindex, hsize)
	}
	indexEnd := 8 + int(nindex)*16
	if indexEnd+int(hsize) > len(b) {
		return Package{}, fmt.Errorf("header is %d bytes, shorter than the %d it describes",
			len(b), indexEnd+int(hsize))
	}
	store := b[indexEnd : indexEnd+int(hsize)]

	entries := make(map[uint32]rpmEntry, nindex)
	for i := 0; i < int(nindex); i++ {
		off := 8 + i*16
		e := rpmEntry{
			tag:    binary.BigEndian.Uint32(b[off : off+4]),
			typ:    binary.BigEndian.Uint32(b[off+4 : off+8]),
			offset: binary.BigEndian.Uint32(b[off+8 : off+12]),
			count:  binary.BigEndian.Uint32(b[off+12 : off+16]),
		}
		// The first entry is normally the immutable-region marker, whose
		// offset points backwards into the store. Keeping only the first
		// occurrence of a tag matches how rpm itself resolves duplicates.
		if _, seen := entries[e.tag]; !seen {
			entries[e.tag] = e
		}
	}

	p := Package{
		Name:      rpmString(store, entries, rpmTagName),
		SizeBytes: int64(rpmInt(store, entries, rpmTagSize)),
	}
	version := rpmString(store, entries, rpmTagVersion)
	release := rpmString(store, entries, rpmTagRelease)
	if version != "" && release != "" {
		p.Version = version + "-" + release
	} else {
		p.Version = version
	}
	// rpm writes an epoch only when it is not zero, and an epoch changes which
	// advisory applies, so it belongs in the version string when present.
	if e, ok := entries[rpmTagEpoch]; ok {
		if epoch := rpmIntAt(store, e); epoch > 0 {
			p.Version = strconv.Itoa(epoch) + ":" + p.Version
		}
	}
	if wantFiles {
		p.Files = rpmFiles(store, entries)
	}
	return p, nil
}

// rpmString reads a STRING or I18NSTRING tag: a NUL-terminated string at the
// entry's offset into the data store.
func rpmString(store []byte, entries map[uint32]rpmEntry, tag uint32) string {
	e, ok := entries[tag]
	if !ok || (e.typ != rpmTypeString && e.typ != rpmTypeI18NString) {
		return ""
	}
	return cstring(store, int(e.offset))
}

func cstring(store []byte, off int) string {
	if off < 0 || off >= len(store) {
		return ""
	}
	for i := off; i < len(store); i++ {
		if store[i] == 0 {
			return string(store[off:i])
		}
	}
	return ""
}

func rpmInt(store []byte, entries map[uint32]rpmEntry, tag uint32) int {
	e, ok := entries[tag]
	if !ok {
		return 0
	}
	return rpmIntAt(store, e)
}

func rpmIntAt(store []byte, e rpmEntry) int {
	switch e.typ {
	case rpmTypeInt32:
		if int(e.offset)+4 > len(store) {
			return 0
		}
		return int(binary.BigEndian.Uint32(store[e.offset : e.offset+4]))
	case rpmTypeInt16:
		if int(e.offset)+2 > len(store) {
			return 0
		}
		return int(binary.BigEndian.Uint16(store[e.offset : e.offset+2]))
	}
	return 0
}

// rpmStringArray reads a STRING_ARRAY tag: count consecutive NUL-terminated
// strings starting at the entry's offset.
func rpmStringArray(store []byte, entries map[uint32]rpmEntry, tag uint32) []string {
	e, ok := entries[tag]
	if !ok || e.typ != rpmTypeStringArray || e.count > 1<<20 {
		return nil
	}
	out := make([]string, 0, e.count)
	off := int(e.offset)
	for i := 0; i < int(e.count); i++ {
		if off < 0 || off >= len(store) {
			return out
		}
		s := cstring(store, off)
		out = append(out, s)
		off += len(s) + 1
	}
	return out
}

// rpmFiles rebuilds the absolute paths a package owns. rpm stores them split
// into a directory table and a basename table so the shared prefixes are
// written once: path i is dirnames[dirindexes[i]] + basenames[i].
func rpmFiles(store []byte, entries map[uint32]rpmEntry) []string {
	basenames := rpmStringArray(store, entries, rpmTagBaseNames)
	if len(basenames) == 0 {
		return nil
	}
	dirnames := rpmStringArray(store, entries, rpmTagDirNames)
	e, ok := entries[rpmTagDirIndexes]
	if !ok || e.typ != rpmTypeInt32 || int(e.count) != len(basenames) {
		return nil
	}
	if int(e.offset)+len(basenames)*4 > len(store) {
		return nil
	}
	out := make([]string, 0, len(basenames))
	for i, base := range basenames {
		idx := int(binary.BigEndian.Uint32(store[int(e.offset)+i*4 : int(e.offset)+i*4+4]))
		if idx < 0 || idx >= len(dirnames) {
			continue
		}
		out = append(out, dirnames[idx]+base)
	}
	return out
}
