package security

import (
	"math"
	"strings"
)

// CVSS v3 base score, computed from the vector string.
//
// OSV reports severity as a vector such as
// CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N and not as a number, so the
// number has to be derived. The alternative is to report "40 vulnerabilities"
// with no sense of whether any of them matter, which is the kind of figure that
// gets an entire report ignored.
//
// The formula is from the CVSS v3.1 specification, section 7.1.

// metric weights. Privileges Required depends on whether scope changed, which
// is the one place the two tables differ.
var (
	attackVector      = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	attackComplexity  = map[string]float64{"L": 0.77, "H": 0.44}
	privRequired      = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	privRequiredScope = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	userInteraction   = map[string]float64{"N": 0.85, "R": 0.62}
	impactMetric      = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
)

// BaseScore computes the CVSS base score for a vector string, and reports
// whether the vector could be understood.
//
// An unparseable or incomplete vector returns false rather than a zero, because
// a score of zero means "harmless" and would quietly downgrade a vulnerability
// that simply used a notation this does not read.
func BaseScore(vector string) (float64, bool) {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			m[k] = v
		}
	}
	if !strings.HasPrefix(vector, "CVSS:3") {
		return 0, false
	}

	scopeChanged := m["S"] == "C"
	pr := privRequired
	if scopeChanged {
		pr = privRequiredScope
	}

	av, ok1 := attackVector[m["AV"]]
	ac, ok2 := attackComplexity[m["AC"]]
	prv, ok3 := pr[m["PR"]]
	ui, ok4 := userInteraction[m["UI"]]
	c, ok5 := impactMetric[m["C"]]
	i, ok6 := impactMetric[m["I"]]
	a, ok7 := impactMetric[m["A"]]
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 {
		return 0, false
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * prv * ui
	score := impact + exploitability
	if scopeChanged {
		score *= 1.08
	}
	return roundUp(math.Min(score, 10)), true
}

// roundUp is CVSS's own rounding: the smallest number to one decimal place that
// is greater than or equal to the input.
//
// The specification defines it in integer arithmetic precisely because the
// obvious floating-point version disagrees with it on values like 4.02, which
// must round to 4.1 rather than 4.0.
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// SeverityOf maps a CVSS base score onto the qualitative bands from the
// specification, which are what a person reading a report actually acts on.
func SeverityOf(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return "none"
}
