package main

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// fakeResolver stands in for the docker CLI so these tests need no daemon.
func fakeResolver(_ context.Context, name, _ string) (string, error) {
	if name == "missing" {
		return "", fmt.Errorf("docker context %q could not be resolved", name)
	}
	return "unix:///fake/" + name + ".sock", nil
}

// TestPluginArgs covers the argv shapes the Docker CLI actually produces.
// Docker puts its own global flags *before* the plugin name, which is what
// made `docker --debug trim` fail outright and, more quietly, what would have
// made `docker --context prod trim` report on the wrong daemon.
func TestPluginArgs(t *testing.T) {
	const name = "trim"
	noEnv := map[string]string{}

	cases := []struct {
		name string
		argv []string
		want []string
		env  map[string]string
	}{
		{"bare", []string{"trim", "--version"}, []string{"--version"}, noEnv},
		{"no arguments of our own", []string{"trim"}, []string{}, noEnv},

		// Presentational flags: dropped, nothing to get wrong.
		{"long bool", []string{"--debug", "trim", "--version"}, []string{"--version"}, noEnv},
		{"short bool", []string{"-D", "trim", "--version"}, []string{"--version"}, noEnv},
		{"long with value", []string{"--log-level", "debug", "trim", "-f", "Dockerfile"}, []string{"-f", "Dockerfile"}, noEnv},
		{"long joined value", []string{"--log-level=debug", "trim", "-q"}, []string{"-q"}, noEnv},
		{"short with value", []string{"-l", "debug", "trim"}, []string{}, noEnv},

		// Daemon selection: honored, or the report describes another machine.
		{"context long", []string{"--context", "prod", "trim", "--image", "api"},
			[]string{"--image", "api"}, map[string]string{"DOCKER_HOST": "unix:///fake/prod.sock"}},
		{"context joined", []string{"--context=prod", "trim"},
			[]string{}, map[string]string{"DOCKER_HOST": "unix:///fake/prod.sock"}},
		{"context short", []string{"-c", "prod", "trim"},
			[]string{}, map[string]string{"DOCKER_HOST": "unix:///fake/prod.sock"}},
		{"context short attached", []string{"-cprod", "trim"},
			[]string{}, map[string]string{"DOCKER_HOST": "unix:///fake/prod.sock"}},
		{"context short joined", []string{"-c=prod", "trim"},
			[]string{}, map[string]string{"DOCKER_HOST": "unix:///fake/prod.sock"}},
		{"shorthand cluster", []string{"-Dc", "prod", "trim", "--osv"},
			[]string{"--osv"}, map[string]string{"DOCKER_HOST": "unix:///fake/prod.sock"}},
		{"host long", []string{"--host", "tcp://d:2375", "trim"},
			[]string{}, map[string]string{"DOCKER_HOST": "tcp://d:2375"}},
		{"host short", []string{"-H", "tcp://d:2375", "trim"},
			[]string{}, map[string]string{"DOCKER_HOST": "tcp://d:2375"}},
		{"config", []string{"--config", "/tmp/cfg", "trim"},
			[]string{}, map[string]string{"DOCKER_CONFIG": "/tmp/cfg"}},

		// A context named "trim" is why the prefix is parsed rather than
		// scanned for the plugin name: the name appears twice, and only the
		// second occurrence is the subcommand.
		{"context named like the plugin", []string{"--context", "trim", "trim", "--image", "z"},
			[]string{"--image", "z"}, map[string]string{"DOCKER_HOST": "unix:///fake/trim.sock"}},

		// A value that looks like a flag is still a value.
		{"flag-shaped value", []string{"-H", "--weird", "trim"},
			[]string{}, map[string]string{"DOCKER_HOST": "--weird"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, env, err := pluginArgs(context.Background(), tc.argv, name, fakeResolver)
			if err != nil {
				t.Fatalf("pluginArgs(%q) = error %v", tc.argv, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("args = %q, want %q", got, tc.want)
			}
			if !reflect.DeepEqual(env, tc.env) {
				t.Errorf("env = %v, want %v", env, tc.env)
			}
		})
	}
}

// TestPluginArgsRefuses covers the flags docker-trim will not guess at. Each
// one selects a daemon or its credentials, so proceeding would mean reporting
// sizes and CVE counts for an image other than the one named.
func TestPluginArgsRefuses(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"tls", []string{"--tls", "trim"}, "--tls cannot be forwarded"},
		{"tlsverify", []string{"--tlsverify", "trim"}, "--tlsverify cannot be forwarded"},
		{"tlscacert", []string{"--tlscacert", "/ca.pem", "trim"}, "--tlscacert cannot be forwarded"},
		{"tlskey", []string{"--tlskey", "/k.pem", "trim"}, "--tlskey cannot be forwarded"},
		{"host and context together", []string{"-H", "tcp://d:2375", "--context", "prod", "trim"},
			"either specify --host or --context, not both"},
		{"missing value", []string{"--context"}, "has no value"},
		{"missing shorthand value", []string{"-c"}, "has no value"},
		{"unresolvable context", []string{"--context", "missing", "trim"}, "could not be resolved"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := pluginArgs(context.Background(), tc.argv, "trim", fakeResolver)
			if err == nil {
				t.Fatalf("pluginArgs(%q) succeeded, want refusal", tc.argv)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestPluginArgsUnknownGlobal documents the fallback for a flag docker grows
// later. It must keep working and must say so, because silence is the one
// outcome that would let a future daemon-selecting flag through unnoticed.
func TestPluginArgsUnknownGlobal(t *testing.T) {
	var buf strings.Builder
	warnOut = &buf
	t.Cleanup(func() { warnOut = os.Stderr })

	got, _, err := pluginArgs(context.Background(), []string{"--future", "trim", "--version"}, "trim", fakeResolver)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := []string{"--version"}; !reflect.DeepEqual(got, want) {
		t.Errorf("args = %q, want %q", got, want)
	}
	if !strings.Contains(buf.String(), "--future") {
		t.Errorf("stderr = %q, want it to name the ignored flag", buf.String())
	}
}

// TestCommandLineWithoutPlugin is the ordinary case: run by name, the
// arguments are already ours and nothing is stripped.
func TestCommandLineWithoutPlugin(t *testing.T) {
	t.Setenv(pluginEnvVar, "")
	argv := os.Args
	os.Args = []string{"docker-trim", "--image", "trim"}
	defer func() { os.Args = argv }()

	got, env, err := commandLine(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"--image", "trim"}; !reflect.DeepEqual(got, want) {
		t.Errorf("args = %q, want %q", got, want)
	}
	if len(env) != 0 {
		t.Errorf("env = %v, want empty", env)
	}
}

func TestPluginName(t *testing.T) {
	for _, tc := range []struct{ argv0, want string }{
		{"docker-trim", "trim"},
		{"/usr/local/bin/docker-trim", "trim"},
		// Windows installs the plugin as docker-trim.exe. The separator in a
		// full Windows path is only understood by filepath on Windows, so the
		// bare name is what this can portably assert.
		{"docker-trim.exe", "trim"},
	} {
		if got := pluginName(tc.argv0); got != tc.want {
			t.Errorf("pluginName(%q) = %q, want %q", tc.argv0, got, tc.want)
		}
	}
}
