package analyzer

import (
	"fmt"
	"strings"
	"testing"
)

// syntheticDockerfile builds a file with n RUN instructions, to see how parsing
// and linting scale with file size.
func syntheticDockerfile(n int) string {
	var b strings.Builder
	b.WriteString("FROM debian:12\nWORKDIR /app\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "RUN apt-get update && apt-get install -y package%d && echo built %d\n", i, i)
	}
	b.WriteString("COPY . .\nCMD [\"/app/server\"]\n")
	return b.String()
}

func BenchmarkParse(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		src := syntheticDockerfile(n)
		b.Run(fmt.Sprintf("instructions=%d", n), func(b *testing.B) {
			b.SetBytes(int64(len(src)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Parse(strings.NewReader(src)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLint(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		a, err := Parse(strings.NewReader(syntheticDockerfile(n)))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("instructions=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				Lint(a)
			}
		})
	}
}

// The end-to-end static path, which is what the performance target describes.
func BenchmarkParseAndLint(b *testing.B) {
	src := syntheticDockerfile(50)
	b.SetBytes(int64(len(src)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a, err := Parse(strings.NewReader(src))
		if err != nil {
			b.Fatal(err)
		}
		Lint(a)
	}
}
