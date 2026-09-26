package analyzer

import (
	"encoding/binary"
	"fmt"
)

// A minimal, read-only SQLite reader: enough to walk one table and hand back
// its rows, and nothing more.
//
// rpm keeps its database in a SQLite file on every RHEL 9 era image, so
// reading it is the only way to inventory those images. The obvious route is
// a SQLite driver, and modernc.org/sqlite is pure Go and would work. It also
// adds 4.5MB to the binary -- measured, against a 1.6MB baseline -- which is a
// poor trade for a tool whose whole purpose is making things smaller and which
// ships its own image. dpkg and apk are already parsed by hand here for the
// same reason.
//
// What this supports is deliberately narrow: table b-trees, overflow chains,
// and the record format. Indices, WAL frames, and writing are all out of
// scope. Anything it does not understand becomes an error rather than a guess,
// because a half-read package database would under-report an image's contents
// and read as though the image were clean.

const sqliteMagic = "SQLite format 3\x00"

// sqliteFile is a parsed database header plus the raw bytes.
type sqliteFile struct {
	data     []byte
	pageSize int
	usable   int // page size less the per-page reserved region
}

func openSQLite(data []byte) (*sqliteFile, error) {
	if len(data) < 100 || string(data[:16]) != sqliteMagic {
		return nil, fmt.Errorf("not a SQLite database")
	}
	// A page size of 1 means 65536, which does not fit the 16-bit field.
	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("invalid page size %d", pageSize)
	}
	usable := pageSize - int(data[20])
	if usable < 480 {
		return nil, fmt.Errorf("invalid reserved region: usable page size %d", usable)
	}
	return &sqliteFile{data: data, pageSize: pageSize, usable: usable}, nil
}

// page returns page n, which is 1-indexed as SQLite numbers them.
func (f *sqliteFile) page(n int) ([]byte, error) {
	if n < 1 {
		return nil, fmt.Errorf("page %d out of range", n)
	}
	start := (n - 1) * f.pageSize
	if start+f.pageSize > len(f.data) {
		return nil, fmt.Errorf("page %d past end of file", n)
	}
	return f.data[start : start+f.pageSize], nil
}

// rootPage finds a table's root page by reading sqlite_master, which always
// lives at page 1 and whose columns are (type, name, tbl_name, rootpage, sql).
func (f *sqliteFile) rootPage(table string) (int, error) {
	rows, err := f.rows(1)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		if len(r) < 4 {
			continue
		}
		name, _ := r[1].(string)
		kind, _ := r[0].(string)
		if kind != "table" || name != table {
			continue
		}
		root, ok := r[3].(int64)
		if !ok || root < 1 {
			return 0, fmt.Errorf("table %q has no usable root page", table)
		}
		return int(root), nil
	}
	return 0, fmt.Errorf("table %q not found", table)
}

// rows walks a table b-tree from the given root and decodes every record.
//
// The walk is iterative with a visited set rather than recursive: the page
// numbers come from the file being read, so a corrupt or hostile database
// could otherwise point a page at itself and spin forever.
func (f *sqliteFile) rows(root int) ([][]any, error) {
	var out [][]any
	visited := map[int]bool{}
	stack := []int{root}

	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if visited[n] {
			return nil, fmt.Errorf("page %d visited twice: the b-tree is not acyclic", n)
		}
		visited[n] = true

		p, err := f.page(n)
		if err != nil {
			return nil, err
		}
		// Page 1 carries the 100-byte file header ahead of its b-tree header.
		off := 0
		if n == 1 {
			off = 100
		}
		if off+12 > len(p) {
			return nil, fmt.Errorf("page %d is truncated", n)
		}
		kind := p[off]
		numCells := int(binary.BigEndian.Uint16(p[off+3 : off+5]))
		headerLen := 8
		if kind == 0x02 || kind == 0x05 {
			headerLen = 12
		}
		if kind != 0x05 && kind != 0x0d {
			return nil, fmt.Errorf("page %d is not a table b-tree page (type %d)", n, kind)
		}
		if kind == 0x05 {
			// Interior page: every child, plus the right-most pointer.
			stack = append(stack, int(binary.BigEndian.Uint32(p[off+8:off+12])))
		}

		ptrs := off + headerLen
		if ptrs+numCells*2 > len(p) {
			return nil, fmt.Errorf("page %d cell pointer array is truncated", n)
		}
		for i := 0; i < numCells; i++ {
			cell := int(binary.BigEndian.Uint16(p[ptrs+i*2 : ptrs+i*2+2]))
			if cell < 0 || cell >= len(p) {
				return nil, fmt.Errorf("page %d cell %d points outside the page", n, i)
			}
			if kind == 0x05 {
				if cell+4 > len(p) {
					return nil, fmt.Errorf("page %d interior cell %d is truncated", n, i)
				}
				stack = append(stack, int(binary.BigEndian.Uint32(p[cell:cell+4])))
				continue
			}
			rec, err := f.leafPayload(p, cell)
			if err != nil {
				return nil, fmt.Errorf("page %d cell %d: %w", n, i, err)
			}
			vals, err := decodeRecord(rec)
			if err != nil {
				return nil, fmt.Errorf("page %d cell %d: %w", n, i, err)
			}
			out = append(out, vals)
		}
	}
	return out, nil
}

// leafPayload reads one table-leaf cell, following the overflow chain when the
// payload is too large to sit on the page.
func (f *sqliteFile) leafPayload(p []byte, cell int) ([]byte, error) {
	payloadLen, k := uvarint(p[cell:])
	if k <= 0 {
		return nil, fmt.Errorf("bad payload length")
	}
	pos := cell + k
	_, k = uvarint(p[pos:]) // rowid, which this reader does not need
	if k <= 0 {
		return nil, fmt.Errorf("bad rowid")
	}
	pos += k

	total := int(payloadLen)
	if total < 0 {
		return nil, fmt.Errorf("payload length %d is negative", payloadLen)
	}
	// How much of the payload lives on this page. These formulas are from the
	// SQLite file format spec; X is the most a table leaf holds without
	// overflowing, and M/K place the split so an overflow page is never used
	// for just a few bytes.
	x := f.usable - 35
	local := total
	if total > x {
		m := ((f.usable - 12) * 32 / 255) - 23
		kk := m + (total-m)%(f.usable-4)
		if kk <= x {
			local = kk
		} else {
			local = m
		}
	}
	if pos+local > len(p) {
		return nil, fmt.Errorf("local payload runs past the page")
	}
	buf := make([]byte, 0, total)
	buf = append(buf, p[pos:pos+local]...)
	if local == total {
		return buf, nil
	}

	if pos+local+4 > len(p) {
		return nil, fmt.Errorf("overflow pointer runs past the page")
	}
	next := int(binary.BigEndian.Uint32(p[pos+local : pos+local+4]))
	seen := map[int]bool{}
	for len(buf) < total {
		if next == 0 {
			return nil, fmt.Errorf("overflow chain ended %d bytes short", total-len(buf))
		}
		if seen[next] {
			return nil, fmt.Errorf("overflow chain loops at page %d", next)
		}
		seen[next] = true
		op, err := f.page(next)
		if err != nil {
			return nil, err
		}
		want := total - len(buf)
		avail := f.usable - 4
		if want > avail {
			want = avail
		}
		if 4+want > len(op) {
			return nil, fmt.Errorf("overflow page %d is truncated", next)
		}
		buf = append(buf, op[4:4+want]...)
		next = int(binary.BigEndian.Uint32(op[0:4]))
	}
	return buf, nil
}

// decodeRecord turns SQLite's record format into Go values. Only the types rpm
// actually stores are produced: integers, text and blobs.
func decodeRecord(rec []byte) ([]any, error) {
	headerLen, k := uvarint(rec)
	if k <= 0 || int(headerLen) > len(rec) || int(headerLen) < k {
		return nil, fmt.Errorf("bad record header")
	}
	var serials []uint64
	for pos := k; pos < int(headerLen); {
		s, n := uvarint(rec[pos:])
		if n <= 0 {
			return nil, fmt.Errorf("bad serial type")
		}
		serials = append(serials, s)
		pos += n
	}

	body := int(headerLen)
	out := make([]any, 0, len(serials))
	for _, s := range serials {
		size, err := serialSize(s)
		if err != nil {
			return nil, err
		}
		if body+size > len(rec) {
			return nil, fmt.Errorf("record value runs past the record")
		}
		raw := rec[body : body+size]
		body += size
		switch {
		case s == 0:
			out = append(out, nil)
		case s >= 1 && s <= 6:
			out = append(out, beInt(raw))
		case s == 8:
			out = append(out, int64(0))
		case s == 9:
			out = append(out, int64(1))
		case s >= 12 && s%2 == 0:
			out = append(out, raw)
		case s >= 13 && s%2 == 1:
			out = append(out, string(raw))
		default:
			// Floats and the reserved types, which rpm does not use.
			out = append(out, nil)
		}
	}
	return out, nil
}

func serialSize(s uint64) (int, error) {
	switch {
	case s == 0, s == 8, s == 9:
		return 0, nil
	case s >= 1 && s <= 4:
		return int(s), nil
	case s == 5:
		return 6, nil
	case s == 6, s == 7:
		return 8, nil
	case s == 10 || s == 11:
		return 0, fmt.Errorf("reserved serial type %d", s)
	default:
		return int((s - 12) / 2), nil
	}
}

// beInt reads a big-endian two's complement integer of 1 to 8 bytes.
func beInt(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	v := int64(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int64(c)
	}
	return v
}

// uvarint decodes SQLite's big-endian varint: up to nine bytes, seven bits
// each, except the ninth which contributes all eight. It returns the value and
// how many bytes it consumed, or n <= 0 if the buffer is too short.
func uvarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 8; i++ {
		if i >= len(b) {
			return 0, 0
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	if len(b) < 9 {
		return 0, 0
	}
	return v<<8 | uint64(b[8]), 9
}
