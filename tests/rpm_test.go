//go:build integration

// rpm inventory, against real RHEL-family images.
//
// The unit tests parse a fixture; this checks the whole path against images
// pulled from a registry, because every serious bug this project has shipped
// lived in a seam between docker-trim and something real rather than inside
// its own parsers.
//
// Run with: make integration
package tests

import (
	"strings"
	"testing"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
	"github.com/mkamranr/docker-trim/pkg/security"
)

// RHEL 9 and its rebuilds keep rpm's database in SQLite, which docker-trim
// reads. Before this existed, every one of these images reported no packages
// at all and could not be scanned for vulnerabilities.
func TestRPMInventory(t *testing.T) {
	ctx := requireDocker(t)

	for _, tc := range []struct {
		image     string
		osID      string
		ecosystem string
		minPkgs   int
		want      string // a package every one of these images has
	}{
		{"redhat/ubi9-minimal", "rhel", "Red Hat", 80, "bash"},
		{"rockylinux:9-minimal", "rocky", "Rocky Linux:9", 80, "bash"},
	} {
		t.Run(tc.image, func(t *testing.T) {
			rep, err := analyzer.InspectImage(ctx, tc.image)
			if err != nil {
				t.Fatalf("InspectImage(%s): %v", tc.image, err)
			}
			if rep.PackageManager != "rpm" {
				t.Errorf("packageManager = %q, want rpm", rep.PackageManager)
			}
			if rep.OSID != tc.osID {
				t.Errorf("osID = %q, want %q", rep.OSID, tc.osID)
			}

			var osPkgs int
			var found bool
			for _, p := range rep.Packages {
				if !p.IsOS() {
					continue
				}
				osPkgs++
				if p.Name == tc.want {
					found = true
					if p.Version == "" {
						t.Errorf("%s has no version", p.Name)
					}
				}
			}
			if osPkgs < tc.minPkgs {
				t.Errorf("%d operating-system packages, want at least %d", osPkgs, tc.minPkgs)
			}
			if !found {
				t.Errorf("%q is not in the inventory", tc.want)
			}
			for _, n := range rep.Notes {
				if strings.Contains(n, "cannot read") || strings.Contains(n, "could not be read") {
					t.Errorf("unexpected note: %s", n)
				}
			}

			// The ecosystem is what turns an inventory into a CVE scan, and
			// getting it wrong returns zero advisories rather than an error.
			eco, err := security.OSVEcosystem(rep)
			if err != nil {
				t.Fatalf("OSVEcosystem: %v", err)
			}
			if eco != tc.ecosystem {
				t.Errorf("ecosystem = %q, want %q", eco, tc.ecosystem)
			}
		})
	}
}

// RHEL 8 still uses Berkeley DB, which is not supported. It has to report that
// plainly: an image with an unreadable database is not an image with no
// packages, and must never be presented as one.
func TestRPMBerkeleyDBIsReportedNotGuessed(t *testing.T) {
	ctx := requireDocker(t)
	rep, err := analyzer.InspectImage(ctx, "redhat/ubi8-minimal")
	if err != nil {
		t.Fatalf("InspectImage: %v", err)
	}
	if rep.PackageManager != "rpm" {
		t.Errorf("packageManager = %q, want rpm", rep.PackageManager)
	}
	var osPkgs int
	for _, p := range rep.Packages {
		if p.IsOS() {
			osPkgs++
		}
	}
	if osPkgs != 0 {
		t.Errorf("%d packages parsed from a Berkeley DB database, want none", osPkgs)
	}
	var explained bool
	for _, n := range rep.Notes {
		if strings.Contains(n, "Berkeley DB") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("no note explains why the inventory is empty; notes were %q", rep.Notes)
	}
}
