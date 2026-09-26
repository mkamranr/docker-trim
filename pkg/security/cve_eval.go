// Package security scores what an attacker could do inside a container and
// reports how much of that a trimmed image takes away.
package security

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/mkamranr/docker-trim/pkg/analyzer"
)

//go:embed surface.json
var surfaceRules []byte

// Entry is one thing worth removing from a production image.
type Entry struct {
	Name   string `json:"name"`
	Class  string `json:"class"`
	Weight int    `json:"weight"`
	Why    string `json:"why"`
}

type ruleset struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

var rules = func() map[string]Entry {
	var rs ruleset
	if err := json.Unmarshal(surfaceRules, &rs); err != nil {
		// The file is embedded at build time and covered by a test, so a
		// failure here means the binary itself is corrupt.
		panic("docker-trim: embedded surface ruleset is invalid: " + err.Error())
	}
	m := make(map[string]Entry, len(rs.Entries))
	for _, e := range rs.Entries {
		m[e.Name] = e
	}
	return m
}()

// Item is one matched piece of attack surface.
type Item struct {
	Name  string `json:"name"`
	Class string `json:"class"`
	Why   string `json:"why"`
}

// Surface is what an image offers an attacker who gets code execution in it.
//
// Score has no absolute meaning; it exists so a before and an after can be
// compared. docker-trim reports the difference, never the number on its own.
type Surface struct {
	Items         []Item `json:"items"`
	Score         int    `json:"score"`
	TotalPackages int    `json:"totalPackages"`
	RunsAsRoot    bool   `json:"runsAsRoot"`
	// Setuid binaries are each a standing escalation primitive.
	Setuid []string `json:"setuidBinaries,omitempty"`
}

// ByClass groups the matched items for display.
func (s Surface) ByClass() map[string][]Item {
	out := map[string][]Item{}
	for _, it := range s.Items {
		out[it.Class] = append(out[it.Class], it)
	}
	return out
}

// Assessment compares an image before and after trimming.
//
// CVEKnown is false unless --osv actually looked the packages up. docker-trim reports
// what it removed, never a vulnerability count it did not measure.
type Assessment struct {
	Original Surface  `json:"original"`
	Trimmed  *Surface `json:"trimmed,omitempty"`
	// Removed lists what the trimmed image no longer carries.
	Removed []Item `json:"removed,omitempty"`
	// RemovedPackages is the drop in installed operating-system packages.
	RemovedPackages int  `json:"removedPackages"`
	CVEKnown        bool `json:"cveKnown"`
	OriginalCVEs    int  `json:"originalCVEs"`
	RemainingCVEs   int  `json:"remainingCVEs"`
	// Notes explain anything docker-trim could not determine.
	Notes []string `json:"notes,omitempty"`
}

// EvaluateImage scores a built image from its package inventory and file list.
func EvaluateImage(rep *analyzer.ImageReport) Surface {
	s := Surface{
		TotalPackages: len(rep.Packages),
		RunsAsRoot:    rep.User == "" || rep.User == "root" || rep.User == "0",
		Setuid:        rep.SetuidBinaries,
	}

	seen := map[string]bool{}
	add := func(name string) {
		e, ok := rules[name]
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		s.Items = append(s.Items, Item{Name: e.Name, Class: e.Class, Why: e.Why})
		s.Score += e.Weight
	}

	for _, p := range rep.Packages {
		add(p.Name)
	}
	// Binaries matter even when no package database claims them, which is the
	// normal case for a distroless or scratch image.
	for _, f := range rep.TopFiles {
		if isBinDir(f.Path) {
			add(path.Base(f.Path))
		}
	}

	// A setuid binary is worth counting whether or not it is on the list.
	s.Score += len(rep.SetuidBinaries) * 3
	if s.RunsAsRoot {
		s.Score += 10
	}

	sortItems(s.Items)
	return s
}

// EvaluateDockerfile scores a Dockerfile without building it, from the packages
// its final stage installs.
func EvaluateDockerfile(a *analyzer.Analysis) Surface {
	s := Surface{RunsAsRoot: true}
	final := a.FinalStage()
	if final == nil {
		return s
	}

	seen := map[string]bool{}
	add := func(name string) {
		e, ok := rules[name]
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		s.Items = append(s.Items, Item{Name: e.Name, Class: e.Class, Why: e.Why})
		s.Score += e.Weight
	}

	for _, ins := range final.Instructions {
		if ins.Keyword == "USER" && len(ins.Args) > 0 && ins.Args[0] != "root" && ins.Args[0] != "0" {
			s.RunsAsRoot = false
		}
		if ins.Keyword != "RUN" || ins.Exec {
			continue
		}
		for _, cmd := range analyzer.Commands(ins.Args) {
			if !analyzer.IsCmd(cmd, "apt-get", "apt", "apk", "yum", "dnf") ||
				!analyzer.HasSubcommand(cmd, "install", "add") {
				continue
			}
			for _, pkg := range analyzer.InstalledPackages(cmd) {
				add(pkg)
				s.TotalPackages++
			}
		}
	}

	// A base image that carries a package manager carries a shell too. Only
	// distroless and scratch genuinely do not.
	base := strings.ToLower(final.BaseImage)
	if !strings.Contains(base, "distroless") && base != "scratch" {
		add("sh")
		if strings.Contains(base, "alpine") {
			add("busybox")
			add("apk-tools")
		} else {
			add("bash")
			add("apt-get")
			add("dpkg")
		}
	}

	if s.RunsAsRoot {
		s.Score += 10
	}
	sortItems(s.Items)
	return s
}

// Compare produces the before and after assessment.
func Compare(original Surface, trimmed *Surface) Assessment {
	a := Assessment{Original: original, Trimmed: trimmed}
	if trimmed == nil {
		return a
	}

	kept := map[string]bool{}
	for _, it := range trimmed.Items {
		kept[it.Name] = true
	}
	for _, it := range original.Items {
		if !kept[it.Name] {
			a.Removed = append(a.Removed, it)
		}
	}
	sortItems(a.Removed)

	if n := original.TotalPackages - trimmed.TotalPackages; n > 0 {
		a.RemovedPackages = n
	}
	a.Notes = append(a.Notes,
		"CVE counts are not reported unless --osv is given: docker-trim does not print a "+
			"vulnerability number it has not measured.")
	return a
}

// Summary renders the one-line attack-surface statement used in the report.
func (a Assessment) Summary() string {
	if a.Trimmed == nil {
		items := fmt.Sprintf("%d shell and tooling %s reachable in the image",
			len(a.Original.Items), pluralWord("item", len(a.Original.Items)))
		if a.Original.TotalPackages > 0 {
			return fmt.Sprintf("%d %s installed, %s", a.Original.TotalPackages,
				pluralWord("package", a.Original.TotalPackages), items)
		}
		return items
	}
	var classes []string
	byClass := map[string]int{}
	for _, it := range a.Removed {
		byClass[it.Class]++
	}
	for _, c := range classOrder {
		if n := byClass[c]; n > 0 {
			classes = append(classes, fmt.Sprintf("%d %s", n, classNoun(c, n)))
		}
	}
	if len(classes) == 0 && a.RemovedPackages == 0 {
		return "unchanged"
	}
	var parts []string
	if a.RemovedPackages > 0 {
		parts = append(parts, fmt.Sprintf("%d unused OS %s", a.RemovedPackages,
			pluralWord("package", a.RemovedPackages)))
	}
	parts = append(parts, classes...)
	return "Removed " + strings.Join(parts, ", ")
}

// classOrder fixes the order classes are listed in, most alarming first.
var classOrder = []string{"shell", "package-manager", "compiler", "network",
	"privilege", "interpreter", "developer-tool"}

// classNoun names a class the way a person would say it out loud.
var classNouns = map[string][2]string{
	"shell":           {"shell", "shells"},
	"package-manager": {"package manager", "package managers"},
	"compiler":        {"compiler", "compilers"},
	"network":         {"network tool", "network tools"},
	"privilege":       {"privilege escalation tool", "privilege escalation tools"},
	"interpreter":     {"script interpreter", "script interpreters"},
	"developer-tool":  {"developer tool", "developer tools"},
}

func pluralWord(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func classNoun(class string, n int) string {
	forms, ok := classNouns[class]
	if !ok {
		return strings.ReplaceAll(class, "-", " ")
	}
	if n == 1 {
		return forms[0]
	}
	return forms[1]
}

func isBinDir(p string) bool {
	dir := path.Dir(p)
	switch dir {
	case "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin":
		return true
	}
	return false
}

func sortItems(items []Item) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Class != items[j].Class {
			return items[i].Class < items[j].Class
		}
		return items[i].Name < items[j].Name
	})
}
