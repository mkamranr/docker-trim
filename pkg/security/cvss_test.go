package security

import (
	"math"
	"testing"
)

// Vectors with scores published by NVD or FIRST. Getting this wrong would
// silently mis-band every vulnerability docker-trim reports, so the arithmetic is
// checked against known answers rather than against itself.
func TestBaseScore_matches_published_scores(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
		name   string
	}{
		// FIRST's own worked examples.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CVE-2019-0708 BlueKeep"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "scope change maxes out"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, "local privilege escalation"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "reflected XSS"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", 3.4, "CVE-2024-11053, verified against NVD"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "denial of service"},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "no impact scores zero"},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "3.0 vectors too"},
	}
	for _, c := range cases {
		got, ok := BaseScore(c.vector)
		if !ok {
			t.Errorf("%s: vector was not understood: %s", c.name, c.vector)
			continue
		}
		if math.Abs(got-c.want) > 0.001 {
			t.Errorf("%s: score = %.1f, want %.1f\n  %s", c.name, got, c.want, c.vector)
		}
	}
}

// A vector this cannot read must not come back as zero, which reads as
// "harmless" and would hide a vulnerability behind a notation problem.
func TestBaseScore_refuses_what_it_cannot_read(t *testing.T) {
	for _, bad := range []string{
		"",
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L",
		"not a vector at all",
	} {
		if score, ok := BaseScore(bad); ok {
			t.Errorf("BaseScore(%q) = %.1f, ok; want it refused", bad, score)
		}
	}
}

// CVSS defines its own rounding because the obvious one disagrees with it.
func TestRoundUp_follows_the_specification(t *testing.T) {
	cases := map[float64]float64{
		4.02:  4.1, // the case plain rounding gets wrong
		4.0:   4.0,
		0.0:   0.0,
		9.999: 10.0,
		3.31:  3.4,
		6.5:   6.5,
	}
	for in, want := range cases {
		if got := roundUp(in); math.Abs(got-want) > 0.001 {
			t.Errorf("roundUp(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestSeverityOf_uses_the_published_bands(t *testing.T) {
	cases := map[float64]string{
		0.0: "none", 0.1: "low", 3.9: "low",
		4.0: "medium", 6.9: "medium",
		7.0: "high", 8.9: "high",
		9.0: "critical", 10.0: "critical",
	}
	for score, want := range cases {
		if got := SeverityOf(score); got != want {
			t.Errorf("SeverityOf(%.1f) = %q, want %q", score, got, want)
		}
	}
}
