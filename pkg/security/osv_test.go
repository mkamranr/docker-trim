package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mkamranr/dtrim/pkg/analyzer"
)

// fakeOSV stands in for api.osv.dev, serving both the batch triage and the
// per-package detail endpoint.
//
// Pointing the tests at the real service would make them fail when it is slow,
// and make the suite depend on vulnerability data that changes daily.
func fakeOSV(t *testing.T, reply map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Triage: which of these packages has any advisory at all. The reply is
	// positional, matching the real API.
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		results := make([]map[string]any, 0, len(req.Queries))
		for _, q := range req.Queries {
			var ids []map[string]string
			if body, ok := reply[q.Package.Name]; ok {
				var parsed struct {
					Vulns []struct{ ID string }
				}
				_ = json.Unmarshal([]byte(body), &parsed)
				for _, v := range parsed.Vulns {
					ids = append(ids, map[string]string{"id": v.ID})
				}
			}
			results = append(results, map[string]any{"vulns": ids})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})

	// Detail: everything known about one package, including CVSS.
	mux.HandleFunc("/v1/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package struct{ Name, Ecosystem string }
			Version string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, ok := reply[req.Package.Name]
		if !ok {
			body = `{"vulns":[]}`
		}
		_, _ = w.Write([]byte(body))
	})

	srv := httptest.NewServer(mux)
	pointAt(t, srv.URL)
	t.Cleanup(srv.Close)
	return srv
}

// pointAt redirects both OSV endpoints at a test server.
func pointAt(t *testing.T, base string) {
	t.Helper()
	oldQuery, oldBatch := osvEndpoint, osvBatchEndpoint
	osvEndpoint, osvBatchEndpoint = base+"/v1/query", base+"/v1/querybatch"
	t.Cleanup(func() { osvEndpoint, osvBatchEndpoint = oldQuery, oldBatch })
}

func debianImage(pkgs ...analyzer.Package) *analyzer.ImageReport {
	return &analyzer.ImageReport{
		Reference: "test:latest", OSID: "debian", OSVersionID: "12", Packages: pkgs,
	}
}

func TestQueryOSV_scores_and_bands_what_it_finds(t *testing.T) {
	fakeOSV(t, map[string]string{
		"curl": `{"vulns":[
			{"id":"DEBIAN-CVE-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
			{"id":"DEBIAN-CVE-2","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N"}]}
		]}`,
		"openssl": `{"vulns":[{"id":"DEBIAN-CVE-3","summary":"a real summary",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}]}]}`,
	})

	rep, err := QueryOSV(context.Background(), debianImage(
		analyzer.Package{Name: "curl", Version: "7.88.1"},
		analyzer.Package{Name: "openssl", Version: "3.0.11"},
		analyzer.Package{Name: "clean-package", Version: "1.0"},
	), nil)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Total != 3 {
		t.Errorf("total = %d, want 3", rep.Total)
	}
	if rep.Queried != 3 {
		t.Errorf("queried = %d, want 3", rep.Queried)
	}
	want := map[string]int{"critical": 1, "high": 1, "low": 1}
	for band, n := range want {
		if rep.BySeverity[band] != n {
			t.Errorf("%s = %d, want %d (all: %v)", band, rep.BySeverity[band], n, rep.BySeverity)
		}
	}
	// Worst first: a report read top-down should lead with what matters.
	if rep.Vulnerabilities[0].Severity != "critical" {
		t.Errorf("first = %s, want the critical one", rep.Vulnerabilities[0].Severity)
	}
	if rep.Vulnerabilities[0].Score != 9.8 {
		t.Errorf("score = %v, want 9.8", rep.Vulnerabilities[0].Score)
	}
	if rep.Vulnerabilities[1].Summary != "a real summary" {
		t.Errorf("the advisory summary was dropped: %+v", rep.Vulnerabilities[1])
	}
}

// One advisory affecting several packages is one problem, not several.
func TestQueryOSV_counts_an_advisory_once(t *testing.T) {
	shared := `{"vulns":[{"id":"DEBIAN-CVE-SHARED","severity":[{"type":"CVSS_V3",
		"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}`
	fakeOSV(t, map[string]string{"a": shared, "b": shared, "c": shared})

	rep, err := QueryOSV(context.Background(), debianImage(
		analyzer.Package{Name: "a", Version: "1"},
		analyzer.Package{Name: "b", Version: "1"},
		analyzer.Package{Name: "c", Version: "1"},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 1 {
		t.Errorf("total = %d, want 1: the same advisory affects all three", rep.Total)
	}
}

// An advisory with no readable score must not be silently banded, because a
// wrong band either fires a gate or, worse, stays quiet.
func TestQueryOSV_admits_when_it_cannot_score_something(t *testing.T) {
	fakeOSV(t, map[string]string{
		"mystery": `{"vulns":[{"id":"DEBIAN-CVE-NOSCORE"}]}`,
		"old":     `{"vulns":[{"id":"DEBIAN-CVE-V2","severity":[{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}]}]}`,
	})

	rep, err := QueryOSV(context.Background(), debianImage(
		analyzer.Package{Name: "mystery", Version: "1"},
		analyzer.Package{Name: "old", Version: "1"},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BySeverity["unknown"] != 2 {
		t.Errorf("unknown = %d, want 2 (all: %v)", rep.BySeverity["unknown"], rep.BySeverity)
	}
	for _, v := range rep.Vulnerabilities {
		if v.ScoreKnown {
			t.Errorf("%s was scored from a vector that cannot be read", v.ID)
		}
	}
}

// An empty result must mean "nothing known", never "the lookup broke".
func TestQueryOSV_fails_loudly_when_every_lookup_fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	pointAt(t, srv.URL)
	t.Cleanup(srv.Close)

	_, err := QueryOSV(context.Background(), debianImage(
		analyzer.Package{Name: "a", Version: "1"},
	), nil)
	if err == nil {
		t.Fatal("a total lookup failure reported no vulnerabilities instead of an error")
	}
}

// A partial failure is a floor, and the report has to say so rather than
// presenting an undercount as a total.
func TestQueryOSV_says_when_a_count_is_only_a_floor(t *testing.T) {
	const vuln = `{"vulns":[{"id":"X","severity":[{"type":"CVSS_V3",
		"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}`

	mux := http.NewServeMux()
	// Triage says every package is affected, so the detail phase has work.
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Queries []json.RawMessage }
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]map[string]any, len(req.Queries))
		for i := range results {
			results[i] = map[string]any{"vulns": []map[string]string{{"id": "X"}}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	// Half the detail lookups fail.
	var n int
	mux.HandleFunc("/v1/query", func(w http.ResponseWriter, _ *http.Request) {
		n++
		if n%2 == 0 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(vuln))
	})

	srv := httptest.NewServer(mux)
	pointAt(t, srv.URL)
	t.Cleanup(srv.Close)

	rep, err := QueryOSV(context.Background(), debianImage(
		analyzer.Package{Name: "a", Version: "1"},
		analyzer.Package{Name: "b", Version: "1"},
		analyzer.Package{Name: "c", Version: "1"},
		analyzer.Package{Name: "d", Version: "1"},
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Notes, " "), "floor") {
		t.Errorf("a partial failure was not disclosed: %v", rep.Notes)
	}
}

// Looking a package up in the wrong distribution returns nothing, which is
// indistinguishable from a clean image. Refusing is the safe answer.
func TestOSVEcosystem(t *testing.T) {
	cases := []struct {
		id, version, want string
		wantErr           bool
	}{
		{"debian", "12", "Debian:12", false},
		{"ubuntu", "22.04", "Ubuntu:22.04", false},
		{"alpine", "3.21.2", "Alpine:v3.21", false}, // OSV tracks the minor release
		{"alpine", "3.21", "Alpine:v3.21", false},
		{"debian", "", "", true},
		{"", "", "", true},
		{"rhel", "9", "", true},
		{"arch", "", "", true},
	}
	for _, c := range cases {
		got, err := OSVEcosystem(&analyzer.ImageReport{OSID: c.id, OSVersionID: c.version})
		if c.wantErr {
			if err == nil {
				t.Errorf("OSVEcosystem(%q,%q) = %q, want an error rather than a wrong lookup",
					c.id, c.version, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("OSVEcosystem(%q,%q): %v", c.id, c.version, err)
			continue
		}
		if got != c.want {
			t.Errorf("OSVEcosystem(%q,%q) = %q, want %q", c.id, c.version, got, c.want)
		}
	}
}

// Each package is looked up in its own ecosystem: a PyPI package in Debian's
// returns nothing, which is indistinguishable from being unaffected.
func TestQueryOSV_looks_each_package_up_in_its_own_ecosystem(t *testing.T) {
	var (
		mu   sync.Mutex
		seen = map[string]string{} // package -> ecosystem it was queried in
	)
	mux := http.NewServeMux()
	record := func(name, eco string) {
		mu.Lock()
		defer mu.Unlock()
		seen[name] = eco
	}
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		results := make([]map[string]any, 0, len(req.Queries))
		for _, q := range req.Queries {
			record(q.Package.Name, q.Package.Ecosystem)
			results = append(results, map[string]any{
				"vulns": []map[string]string{{"id": "ADV-" + q.Package.Name}},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("/v1/query", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Package struct{ Name, Ecosystem string }
			Version string
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		record(req.Package.Name, req.Package.Ecosystem)
		_, _ = w.Write([]byte(`{"vulns":[{"id":"ADV-` + req.Package.Name + `","severity":[{"type":"CVSS_V3",` +
			`"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}`))
	})
	srv := httptest.NewServer(mux)
	pointAt(t, srv.URL)
	t.Cleanup(srv.Close)

	rep, err := QueryOSV(context.Background(), debianImage(
		analyzer.Package{Name: "curl", Version: "7.88.1"},
		analyzer.Package{Name: "flask", Version: "3.1.0", Ecosystem: "PyPI", Root: "/usr/lib/python3/site-packages"},
		analyzer.Package{Name: "express", Version: "4.21.2", Ecosystem: "npm", Root: "/app/node_modules"},
	), nil)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{"curl": "Debian:12", "flask": "PyPI", "express": "npm"}
	for name, eco := range want {
		if seen[name] != eco {
			t.Errorf("%s was looked up in %q, want %q", name, seen[name], eco)
		}
	}
	if rep.Total != 3 {
		t.Errorf("total = %d, want 3", rep.Total)
	}
	// And the report keeps them apart.
	byEco := map[string]EcosystemReport{}
	for _, e := range rep.Ecosystems {
		byEco[e.Ecosystem] = e
	}
	if len(byEco) != 3 {
		t.Fatalf("ecosystems = %+v, want three", rep.Ecosystems)
	}
	if got := byEco["npm"].Roots["/app/node_modules"]; got != 1 {
		t.Errorf("npm roots = %v, want the install root recorded", byEco["npm"].Roots)
	}
}

// An unfamiliar distribution must not stop the language packages being
// scanned: reporting nothing because the base was unusual is the wrong silence.
func TestQueryOSV_scans_language_packages_on_an_unknown_distro(t *testing.T) {
	fakeOSV(t, map[string]string{
		"flask": `{"vulns":[{"id":"PYSEC-1","severity":[{"type":"CVSS_V3",
			"score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}`,
	})

	rep, err := QueryOSV(context.Background(), &analyzer.ImageReport{
		Reference: "test:latest", OSID: "gentoo", // not supported
		Packages: []analyzer.Package{
			{Name: "glibc", Version: "2.39"},
			{Name: "flask", Version: "3.1.0", Ecosystem: "PyPI"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("an unknown distro stopped the whole scan: %v", err)
	}
	if rep.Total != 1 {
		t.Errorf("total = %d, want the PyPI advisory", rep.Total)
	}
	if rep.Queried != 1 {
		t.Errorf("queried = %d, want only the package with a known ecosystem", rep.Queried)
	}
	if len(rep.Notes) == 0 || !strings.Contains(strings.Join(rep.Notes, " "), "not looked up") {
		t.Errorf("the skipped OS packages were not disclosed: %v", rep.Notes)
	}
}
