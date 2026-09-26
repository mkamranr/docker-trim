// This file is the Docker CLI plugin surface: the parts of docker-trim that
// exist only because it can be invoked as `docker trim` rather than by name.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mkamranr/docker-trim/internal/version"
)

// pluginEnvVar is set by the Docker CLI when it invokes a plugin, and by
// nothing else. Its presence is the only reliable signal that the leading
// arguments belong to docker rather than to the user.
const pluginEnvVar = "DOCKER_CLI_PLUGIN_ORIGINAL_CLI_COMMAND"

// disposition is what docker-trim does about one of docker's global flags.
type disposition int

const (
	// ignoreFlag: presentational only. Dropping it changes nothing we report.
	ignoreFlag disposition = iota
	// honorFlag: selects a daemon or credentials, and has a faithful
	// environment equivalent we can set.
	honorFlag
	// refuseFlag: selects a daemon, with no equivalent we can express.
	// Refusing to run is the honest outcome; analyzing a different daemon
	// than the user named and reporting its numbers is not.
	refuseFlag
)

type dockerGlobal struct {
	takesValue  bool
	disposition disposition
}

// dockerGlobals is every global flag the Docker CLI accepts, from
// `docker --help`.
//
// Docker forwards its own global flags to a plugin verbatim and *ahead of* the
// plugin name: `docker --context prod trim --image api` reaches us as
//
//	["--context", "prod", "trim", "--image", "api"]
//
// and docker sets no environment variable to compensate -- DOCKER_CONTEXT and
// DOCKER_HOST are both absent from a plugin's environment. So each flag has to
// be accounted for by hand. Skipping the whole prefix would be a one-line fix
// and a silent correctness bug: `--context prod` would be discarded and every
// size and CVE number in the report would describe the default daemon's image
// while naming the user's.
var dockerGlobals = map[string]dockerGlobal{
	"--debug":     {false, ignoreFlag},
	"-D":          {false, ignoreFlag},
	"--log-level": {true, ignoreFlag},
	"-l":          {true, ignoreFlag},

	"--context": {true, honorFlag},
	"-c":        {true, honorFlag},
	"--host":    {true, honorFlag},
	"-H":        {true, honorFlag},
	"--config":  {true, honorFlag},

	// TLS is refused rather than honored because the two vocabularies do not
	// round-trip: docker takes three independent file paths, while the docker
	// client library that go-containerregistry uses takes one directory with
	// fixed member names (DOCKER_CERT_PATH). Guessing a directory from three
	// paths would mean connecting with credentials the user did not choose.
	"--tls":       {false, refuseFlag},
	"--tlsverify": {false, refuseFlag},
	"--tlscacert": {true, refuseFlag},
	"--tlscert":   {true, refuseFlag},
	"--tlskey":    {true, refuseFlag},
}

// pluginName is the subcommand docker knows us by: docker-trim -> "trim".
// On Windows the binary is docker-trim.exe, so the extension comes off first.
func pluginName(argv0 string) string {
	base := filepath.Base(argv0)
	return strings.TrimPrefix(strings.TrimSuffix(base, filepath.Ext(base)), "docker-")
}

// commandLine is the arguments cobra should parse, plus the environment
// docker's global flags imply.
//
// When docker-trim is run by name the arguments are already ours and this is
// the identity function. As a plugin, docker's flags and the matched
// subcommand have to come off the front first; left in place the subcommand
// parses as a positional argument, so `docker trim -f Dockerfile` went looking
// for an image called "trim".
func commandLine(ctx context.Context) ([]string, map[string]string, error) {
	argv := os.Args[1:]
	if os.Getenv(pluginEnvVar) == "" {
		return argv, nil, nil
	}
	name := pluginName(os.Args[0])
	if name == "" {
		return argv, nil, nil
	}
	return pluginArgs(ctx, argv, name, dockerContextHost)
}

// contextResolver turns a docker context name into a daemon endpoint. It is a
// parameter so the tests do not need a docker installation.
type contextResolver func(ctx context.Context, name string, dockerConfig string) (string, error)

// pluginArgs splits a plugin invocation into the environment docker's global
// flags imply and the arguments that are actually ours.
func pluginArgs(ctx context.Context, argv []string, name string, resolve contextResolver) ([]string, map[string]string, error) {
	env := map[string]string{}
	var host, contextName string

	// apply records one recognized global flag, or rejects it.
	apply := func(flag, value string) error {
		g := dockerGlobals[flag]
		switch g.disposition {
		case ignoreFlag:
			return nil
		case refuseFlag:
			return fmt.Errorf("docker's %s cannot be forwarded through a plugin; "+
				"run docker-trim directly with DOCKER_HOST and DOCKER_CERT_PATH set instead", flag)
		}
		switch flag {
		case "--context", "-c":
			contextName = value
		case "--host", "-H":
			host = value
		case "--config":
			env["DOCKER_CONFIG"] = value
		}
		return nil
	}

	i := 0
scan:
	for ; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == name:
			i++
			break scan
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			// Not a flag and not our name. Docker does not produce this; stop
			// interpreting and let cobra report whatever it is.
			break scan
		case strings.HasPrefix(arg, "--"):
			flag, value := arg, ""
			hasValue := false
			if eq := strings.IndexByte(arg, '='); eq >= 0 {
				flag, value, hasValue = arg[:eq], arg[eq+1:], true
			}
			g, known := dockerGlobals[flag]
			if !known {
				return unknownGlobal(argv, i, name, flag, env)
			}
			if g.takesValue && !hasValue {
				if i+1 >= len(argv) {
					return nil, nil, fmt.Errorf("docker option %s has no value", flag)
				}
				i++
				value = argv[i]
			}
			if err := apply(flag, value); err != nil {
				return nil, nil, err
			}
		default:
			// A shorthand cluster: -D, -Dc prod, -cprod, -c=prod.
			cluster := arg[1:]
			for j := 0; j < len(cluster); j++ {
				flag := "-" + string(cluster[j])
				g, known := dockerGlobals[flag]
				if !known {
					return unknownGlobal(argv, i, name, flag, env)
				}
				if !g.takesValue {
					if err := apply(flag, ""); err != nil {
						return nil, nil, err
					}
					continue
				}
				value := strings.TrimPrefix(cluster[j+1:], "=")
				if value == "" {
					if i+1 >= len(argv) {
						return nil, nil, fmt.Errorf("docker option %s has no value", flag)
					}
					i++
					value = argv[i]
				}
				if err := apply(flag, value); err != nil {
					return nil, nil, err
				}
				break
			}
		}
	}

	switch {
	case host != "" && contextName != "":
		// The same refusal docker itself gives, rather than silently picking.
		return nil, nil, fmt.Errorf("conflicting docker options: either specify --host or --context, not both")
	case host != "":
		env["DOCKER_HOST"] = host
	case contextName != "":
		resolved, err := resolve(ctx, contextName, env["DOCKER_CONFIG"])
		if err != nil {
			return nil, nil, err
		}
		env["DOCKER_HOST"] = resolved
	}
	return argv[i:], env, nil
}

// unknownGlobal handles a flag docker has grown since this table was written.
//
// We cannot tell whether it consumes the next argument, so the prefix can no
// longer be parsed; fall back to locating the plugin name. Saying so out loud
// matters: silence is the one outcome that would let a future daemon-selecting
// flag through unnoticed.
func unknownGlobal(argv []string, from int, name, flag string, env map[string]string) ([]string, map[string]string, error) {
	_, _ = fmt.Fprintf(warnOut, "docker-trim: ignoring unrecognized docker option %s; "+
		"if it selects a daemon, run docker-trim directly instead\n", flag)
	for i := from; i < len(argv); i++ {
		if argv[i] == name {
			return argv[i+1:], env, nil
		}
	}
	return nil, env, nil
}

// warnOut is where plugin-level warnings go. A variable so the tests can read
// them back without a pipe.
var warnOut io.Writer = os.Stderr

// dockerContextHost resolves a context name to the daemon endpoint it names.
//
// This translation is the entire reason --context is handled rather than
// forwarded: DOCKER_CONTEXT is understood only by the docker CLI, while image
// inspection goes through go-containerregistry, whose client is built with
// client.FromEnv and has never heard of contexts. Setting DOCKER_CONTEXT alone
// would send the tracer and the inspector to two different daemons in a single
// run -- the worst of the available failures, because it would still produce a
// plausible-looking report.
func dockerContextHost(ctx context.Context, name, dockerConfig string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("--context %s needs the docker CLI to resolve, and it is not on PATH", name)
	}
	cmd := exec.CommandContext(ctx, "docker", "context", "inspect", name,
		"--format", "{{.Endpoints.docker.Host}}\t{{len .TLSMaterial}}")
	if dockerConfig != "" {
		cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+dockerConfig)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker context %q could not be resolved: %w", name, err)
	}
	host, tls, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
	if host == "" {
		return "", fmt.Errorf("docker context %q names no daemon endpoint", name)
	}
	if tls != "" && tls != "0" {
		// Same reasoning as the TLS flags: the certificates live in the
		// context store under names we would have to guess at.
		return "", fmt.Errorf("docker context %q carries TLS material, which cannot be forwarded "+
			"through a plugin; run docker-trim directly with DOCKER_HOST and DOCKER_CERT_PATH set instead", name)
	}
	return host, nil
}

// pluginMetadataCommand makes docker-trim usable as `docker trim`.
//
// The Docker CLI treats any executable named docker-<name> in its plugin
// directory as a subcommand, and asks it for this one hidden command to learn
// what it is. Answering costs a few lines, and without it Docker reports a
// binary carrying exactly this naming convention as an invalid plugin, which
// is a confusing way to greet someone who put it where the name suggests.
//
// Install with:
//
//	mkdir -p ~/.docker/cli-plugins
//	ln -sf "$(command -v docker-trim)" ~/.docker/cli-plugins/docker-trim
func pluginMetadataCommand() *cobra.Command {
	return &cobra.Command{
		Use:    "docker-cli-plugin-metadata",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{
				"SchemaVersion":    "0.1.0",
				"Vendor":           "mkamranr",
				"Version":          version.Version(),
				"ShortDescription": "Shrink container images and cut their attack surface",
				"URL":              "https://github.com/mkamranr/docker-trim",
			})
		},
	}
}
