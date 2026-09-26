package analyzer

import (
	"strings"
	"testing"
)

// Matching on the shape of the path is what keeps a package.json belonging to a
// test fixture or an example out of the inventory, and what makes nesting work
// without special handling.
func TestIsNpmManifest(t *testing.T) {
	yes := []string{
		"/app/node_modules/express/package.json",
		"/app/node_modules/@babel/core/package.json",
		"/app/node_modules/a/node_modules/b/package.json",
		"/app/node_modules/@scope/a/node_modules/@other/b/package.json",
		"/usr/local/lib/node_modules/npm/node_modules/chalk/package.json",
	}
	no := []string{
		"/app/package.json", // the project itself, not an installed package
		"/app/node_modules/express/test/fixtures/package.json", // a fixture
		"/app/node_modules/express/lib/package.json",
		"/app/src/package.json",
		"/app/node_modules/package.json", // no package directory
		"/app/node_modules/express/package-lock.json",
	}
	for _, p := range yes {
		if !isNpmManifest(p) {
			t.Errorf("isNpmManifest(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isNpmManifest(p) {
			t.Errorf("isNpmManifest(%q) = true, want false", p)
		}
	}
}

func TestIsPythonMetadata(t *testing.T) {
	yes := []string{
		"/usr/local/lib/python3.12/site-packages/flask-3.1.0.dist-info/METADATA",
		"/usr/lib/python3/dist-packages/requests-2.31.0.egg-info/PKG-INFO",
		"/app/.venv/lib/python3.11/site-packages/Jinja2-3.1.2.dist-info/METADATA",
	}
	no := []string{
		"/app/METADATA",
		"/usr/local/lib/python3.12/site-packages/flask/METADATA", // not a dist-info dir
		"/app/docs/PKG-INFO",
		"/usr/local/lib/python3.12/site-packages/flask-3.1.0.dist-info/RECORD",
	}
	for _, p := range yes {
		if !isPythonMetadata(p) {
			t.Errorf("isPythonMetadata(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isPythonMetadata(p) {
			t.Errorf("isPythonMetadata(%q) = true, want false", p)
		}
	}
}

// METADATA is RFC 822 shaped and the long description follows a blank line.
// Reading past it would pull megabytes of README into memory for nothing.
func TestParsePythonMetadata(t *testing.T) {
	const body = `Metadata-Version: 2.1
Name: Flask
Version: 3.1.0
Summary: A simple framework
License: BSD-3-Clause

This is the long description, which mentions
Name: NotTheRealName
Version: 999.0
`
	name, version := parsePythonMetadata([]byte(body))
	if name != "Flask" || version != "3.1.0" {
		t.Errorf("got %q %q, want Flask 3.1.0", name, version)
	}
}

func TestParseNpmManifest(t *testing.T) {
	name, version := parseNpmManifest([]byte(`{"name":"@babel/core","version":"7.24.0","main":"x"}`))
	if name != "@babel/core" || version != "7.24.0" {
		t.Errorf("got %q %q", name, version)
	}
	// The parser reports what it read; the inventory decides what is usable.
	if n, v := parseNpmManifest([]byte(`{"name":"workspace-root"}`)); n == "" || v != "" {
		t.Errorf("got %q %q, want the name and an empty version", n, v)
	}
	if n, _ := parseNpmManifest([]byte(`not json`)); n != "" {
		t.Error("invalid JSON produced a package")
	}
}

// A workspace root or private stub carries no version, and nothing can be
// looked up without one, so it must never reach the inventory.
func TestCaptureLanguage_skips_manifests_with_no_version(t *testing.T) {
	d := newPackageDB(false)
	for _, body := range []string{
		`{"name":"workspace-root"}`,
		`{"private":true}`,
		`not json at all`,
	} {
		if !d.captureLanguage("/app/node_modules/x/package.json", strings.NewReader(body)) {
			t.Errorf("the path was not recognised as an npm manifest: %s", body)
		}
	}
	if got := len(d.languagePackages()); got != 0 {
		t.Errorf("packages = %d, want none: not one of those can be looked up", got)
	}

	// And a complete one is recorded.
	if !d.captureLanguage("/app/node_modules/express/package.json",
		strings.NewReader(`{"name":"express","version":"4.21.2"}`)) {
		t.Fatal("a valid manifest was not recognised")
	}
	pkgs := d.languagePackages()
	if len(pkgs) != 1 || pkgs[0].Name != "express" || pkgs[0].Version != "4.21.2" {
		t.Errorf("packages = %+v", pkgs)
	}
}

// OSV normalises PyPI names itself, so this exists purely so the same
// distribution is not counted twice under two spellings.
func TestNormalisePyPI(t *testing.T) {
	cases := map[string]string{
		"Jinja2":           "jinja2",
		"Flask-SQLAlchemy": "flask-sqlalchemy",
		"flask_sqlalchemy": "flask-sqlalchemy",
		"zope.interface":   "zope-interface",
		"ruamel.yaml.clib": "ruamel-yaml-clib",
		"  Requests  ":     "requests",
	}
	for in, want := range cases {
		if got := normalisePyPI(in); got != want {
			t.Errorf("normalisePyPI(%q) = %q, want %q", in, got, want)
		}
	}
}

// The outermost tree is the one the user installed; a copy vendored inside
// another dependency belongs to it.
func TestInstallRoot(t *testing.T) {
	cases := map[string]string{
		"/app/node_modules/express/package.json":                      "/app/node_modules",
		"/app/node_modules/a/node_modules/b/package.json":             "/app/node_modules",
		"/usr/local/lib/node_modules/npm/node_modules/c/package.json": "/usr/local/lib/node_modules",
		"/nowhere/package.json":                                       "",
	}
	for in, want := range cases {
		if got := installRoot(in, "node_modules"); got != want {
			t.Errorf("installRoot(%q) = %q, want %q", in, got, want)
		}
	}
	if got := installRoot("/usr/lib/python3/dist-packages/x-1.0.dist-info/METADATA",
		"site-packages", "dist-packages"); got != "/usr/lib/python3/dist-packages" {
		t.Errorf("dist-packages root = %q", got)
	}
}

// Nested node_modules install the same package many times. Without dedup an
// image reports several hundred copies of one dependency and queries OSV for
// each.
func TestAddLang_dedups_and_keeps_the_shallowest_root(t *testing.T) {
	d := newPackageDB(false)
	d.addLang(langPackage{name: "ms", version: "2.1.3", ecosystem: EcosystemNpm,
		root: "/app/node_modules/express/node_modules"})
	d.addLang(langPackage{name: "ms", version: "2.1.3", ecosystem: EcosystemNpm,
		root: "/app/node_modules"})
	d.addLang(langPackage{name: "ms", version: "2.1.3", ecosystem: EcosystemNpm,
		root: "/app/node_modules/send/node_modules"})
	// A different version is a different package.
	d.addLang(langPackage{name: "ms", version: "2.0.0", ecosystem: EcosystemNpm,
		root: "/app/node_modules"})

	pkgs := d.languagePackages()
	if len(pkgs) != 2 {
		t.Fatalf("packages = %d, want 2 (one per version)", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Version == "2.1.3" && p.Root != "/app/node_modules" {
			t.Errorf("root = %q, want the shallowest tree", p.Root)
		}
		if p.Ecosystem != EcosystemNpm {
			t.Errorf("ecosystem = %q", p.Ecosystem)
		}
		if p.IsOS() {
			t.Error("a language package reported itself as an OS package")
		}
	}
}

// An image with thousands of small metadata files must not be read entirely
// into memory.
func TestAddLang_stops_at_the_cap(t *testing.T) {
	d := newPackageDB(false)
	for i := 0; i < maxLangPackages+50; i++ {
		d.addLang(langPackage{
			name:    "pkg" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + itoa(i),
			version: "1.0.0", ecosystem: EcosystemNpm,
		})
	}
	if len(d.langPackages) > maxLangPackages {
		t.Errorf("packages = %d, want no more than %d", len(d.langPackages), maxLangPackages)
	}
	if !d.langTruncated {
		t.Error("the inventory was truncated without recording that it was")
	}
	_, _, notes := d.parse()
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, " "), "floor") {
		t.Errorf("truncation was not disclosed: %v", notes)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
