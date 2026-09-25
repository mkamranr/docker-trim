package analyzer

import (
	"strings"
	"testing"
)

func imageWith(pkgs ...Package) *ImageReport {
	return &ImageReport{Reference: "test:latest", PackageManager: "dpkg", Packages: pkgs}
}

func names(pkgs []Package) string {
	var out []string
	for _, p := range pkgs {
		out = append(out, p.Name)
	}
	return strings.Join(out, ",")
}

func TestAttributeUsage_splits_touched_from_untouched(t *testing.T) {
	rep := imageWith(
		Package{Name: "python3", SizeBytes: 10 << 20, Files: []string{"/usr/bin/python3"}},
		Package{Name: "gcc", SizeBytes: 70 << 20, Files: []string{"/usr/bin/gcc", "/usr/lib/gcc/x.o"}},
		Package{Name: "libssl3", SizeBytes: 5 << 20, Files: []string{"/usr/lib/libssl.so.3"}},
	)
	u := AttributeUsage(rep, TraceManifest{
		UsedBinaries: []string{"/usr/bin/python3"},
		SharedLibs:   []string{"/usr/lib/libssl.so.3"},
	})

	if got := names(u.Used); got != "python3,libssl3" && got != "libssl3,python3" {
		t.Errorf("used = %q, want python3 and libssl3", got)
	}
	if got := names(u.Unused); got != "gcc" {
		t.Errorf("unused = %q, want gcc", got)
	}
	if u.RemovableBytes != 70<<20 {
		t.Errorf("removable = %d bytes, want gcc's 70MB", u.RemovableBytes)
	}
}

// A short trace never opens the trust store, never resolves a time zone and
// never re-runs the dynamic loader. Reporting those as removable would hand
// someone a broken image.
func TestAttributeUsage_never_suggests_removing_what_boots_the_image(t *testing.T) {
	rep := imageWith(
		Package{Name: "libc6", Files: []string{"/usr/lib/libc.so.6"}},
		Package{Name: "ca-certificates", Files: []string{"/etc/ssl/certs/ca-certificates.crt"}},
		Package{Name: "tzdata", Files: []string{"/usr/share/zoneinfo/UTC"}},
		Package{Name: "musl", Files: []string{"/lib/ld-musl-x86_64.so.1"}},
		Package{Name: "vim", SizeBytes: 40 << 20, Files: []string{"/usr/bin/vim"}},
	)
	u := AttributeUsage(rep, TraceManifest{UsedBinaries: []string{"/bin/true"}})

	for _, p := range u.Unused {
		switch p.Name {
		case "libc6", "ca-certificates", "tzdata", "musl":
			t.Errorf("%s was reported as removable; removing it breaks the image", p.Name)
		}
	}
	if got := names(u.Unused); got != "vim" {
		t.Errorf("unused = %q, want vim only", got)
	}
	if len(u.Essential) != 4 {
		t.Errorf("essential = %q, want the four that boot the image", names(u.Essential))
	}
}

func TestAttributeUsage_reports_files_no_package_owns(t *testing.T) {
	rep := imageWith(Package{Name: "python3", Files: []string{"/usr/bin/python3"}})
	u := AttributeUsage(rep, TraceManifest{
		UsedBinaries:  []string{"/usr/bin/python3"},
		AccessedFiles: []string{"/app/main.py", "/app/config.yaml"},
	})

	if len(u.UnownedFiles) != 2 {
		t.Errorf("unowned = %v, want the two application files", u.UnownedFiles)
	}
	if u.UnownedFiles[0] != "/app/config.yaml" {
		t.Errorf("unowned files should be sorted, got %v", u.UnownedFiles)
	}
}

func TestAttributeUsage_says_so_when_it_cannot_attribute(t *testing.T) {
	// An image whose package database records no file ownership.
	rep := imageWith(Package{Name: "python3"})
	u := AttributeUsage(rep, TraceManifest{UsedBinaries: []string{"/usr/bin/python3"}})
	if len(u.Notes) == 0 {
		t.Fatal("no note explaining that attribution was impossible")
	}
	if len(u.Unused) != 0 {
		t.Errorf("reported %d unused packages despite having no ownership data", len(u.Unused))
	}

	// And an image with no inventory at all.
	empty := AttributeUsage(&ImageReport{Reference: "x"}, TraceManifest{})
	if len(empty.Notes) == 0 {
		t.Error("no note explaining the missing package inventory")
	}
}

func TestParseApkInstalled_reassembles_file_paths(t *testing.T) {
	// apk records a directory, then the names inside it.
	const db = "P:busybox\nV:1.37.0-r31\nI:1024\nF:bin\nR:busybox\nR:sh\nF:usr/bin\nR:awk\n\n"
	pkgs := parseApkInstalled([]byte(db))
	attachApkFiles(pkgs, []byte(db))

	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1", len(pkgs))
	}
	want := map[string]bool{"/bin/busybox": true, "/bin/sh": true, "/usr/bin/awk": true}
	if len(pkgs[0].Files) != len(want) {
		t.Fatalf("files = %v, want %v", pkgs[0].Files, want)
	}
	for _, f := range pkgs[0].Files {
		if !want[f] {
			t.Errorf("unexpected path %q", f)
		}
	}
}

func TestAttachDpkgFiles_ignores_directories(t *testing.T) {
	pkgs := []Package{{Name: "curl"}}
	attachDpkgFiles(pkgs, map[string][]byte{
		// dpkg lists directories alongside files; a directory is owned by many
		// packages at once and says nothing about which is in use.
		"curl": []byte("/usr\n/usr/bin\n/usr/bin/curl\n/usr/share/doc/curl/\n"),
	})
	for _, f := range pkgs[0].Files {
		if strings.HasSuffix(f, "/") {
			t.Errorf("directory %q was recorded as an owned file", f)
		}
	}
	if len(pkgs[0].Files) != 3 {
		t.Errorf("files = %v", pkgs[0].Files)
	}
}

// Debian's "important" priority means "expected on a Unix-like system", not
// "required to boot". Treating it as untouchable hid vim-tiny, nano, less and
// procps from every trace, which is most of what a container can safely lose.
func TestParseDpkgStatus_only_required_priority_counts_as_essential(t *testing.T) {
	const status = `Package: bash
Status: install ok installed
Priority: required
Essential: yes
Installed-Size: 7000

Package: vim-tiny
Status: install ok installed
Priority: important
Installed-Size: 1500

Package: curl
Status: install ok installed
Priority: optional
Installed-Size: 500

`
	pkgs := parseDpkgStatus([]byte(status))
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Name] = p.Essential
	}
	if len(pkgs) != 3 {
		t.Fatalf("packages = %d, want 3", len(pkgs))
	}
	if !got["bash"] {
		t.Error("bash is Essential: yes and Priority: required, so it must be essential")
	}
	if got["vim-tiny"] {
		t.Error(`vim-tiny is Priority: important, which does not make it essential`)
	}
	if got["curl"] {
		t.Error("curl is Priority: optional and must not be essential")
	}
}

func TestParseDpkgStatus_skips_packages_that_are_not_installed(t *testing.T) {
	const status = `Package: gone
Status: deinstall ok config-files
Installed-Size: 100

Package: here
Status: install ok installed
Installed-Size: 100

`
	pkgs := parseDpkgStatus([]byte(status))
	if len(pkgs) != 1 || pkgs[0].Name != "here" {
		t.Errorf("packages = %+v, want only the installed one", pkgs)
	}
}

// A traced open records the path the loader actually asked for, which is
// usually /lib/..., while dpkg records the same file under /usr/lib/... because
// /lib is a symlink. Failing to reconcile the two makes every library look
// unowned and every library package look unused, which is the most dangerous
// way this tool could be wrong.
func TestAttributeUsage_reconciles_usrmerge_paths(t *testing.T) {
	rep := imageWith(
		Package{Name: "libc6", Files: []string{"/usr/lib/x86_64-linux-gnu/libc.so.6"}},
		Package{Name: "libsqlite3-0", SizeBytes: 2 << 20,
			Files: []string{"/usr/lib/x86_64-linux-gnu/libsqlite3.so.0"}},
		Package{Name: "coreutils", Files: []string{"/usr/bin/cat"}},
	)
	// What a trace actually reports.
	u := AttributeUsage(rep, TraceManifest{
		SharedLibs:   []string{"/lib/x86_64-linux-gnu/libsqlite3.so.0"},
		UsedBinaries: []string{"/bin/cat"},
	})

	used := map[string]bool{}
	for _, p := range u.Used {
		used[p.Name] = true
	}
	if !used["libsqlite3-0"] {
		t.Error("/lib/.../libsqlite3.so.0 was not matched to the package owning /usr/lib/...")
	}
	if !used["coreutils"] {
		t.Error("/bin/cat was not matched to the package owning /usr/bin/cat")
	}
	for _, p := range u.Unused {
		if p.Name == "libsqlite3-0" || p.Name == "coreutils" {
			t.Errorf("%s was used but reported as removable", p.Name)
		}
	}
	if len(u.UnownedFiles) != 0 {
		t.Errorf("unowned = %v, want none: every path belongs to a package", u.UnownedFiles)
	}
}

func TestPathAliases(t *testing.T) {
	cases := map[string][]string{
		"/lib/x86_64-linux-gnu/libc.so.6":     {"/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6"},
		"/usr/lib/x86_64-linux-gnu/libc.so.6": {"/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"},
		"/bin/sh":                             {"/bin/sh", "/usr/bin/sh"},
		"/sbin/init":                          {"/sbin/init", "/usr/sbin/init"},
		// Nothing outside the merged directories should grow an alias.
		"/etc/hosts":     {"/etc/hosts"},
		"/app/config.py": {"/app/config.py"},
	}
	for in, want := range cases {
		got := pathAliases(in)
		if len(got) != len(want) {
			t.Errorf("pathAliases(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("pathAliases(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}
