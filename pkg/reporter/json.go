package reporter

import (
	"encoding/json"
	"io"

	"github.com/mkamranr/docker-trim/pkg/trim"
)

// JSON writes the machine-readable report to w.
//
// The shape is versioned by trim.SchemaVersion so a CI job can pin to it. It
// is what --quiet emits, on stdout, with nothing else mixed in.
func JSON(w io.Writer, rep *trim.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
