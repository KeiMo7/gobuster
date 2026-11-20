package dir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OJ/gobuster/v3/libgobuster"
	"github.com/urfave/cli/v2"
)

func runDirCommand(t *testing.T, args ...string) error {
	t.Helper()

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	app := &cli.App{
		Name:     "gobuster",
		Commands: []*cli.Command{Command()},
	}

	fullArgs := append([]string{
		"gobuster", "dir",
		"-u", "http://127.0.0.1:1",
		"-w", wordlist,
		"--no-progress",
		"--no-error",
		"--quiet",
	}, args...)

	return app.Run(fullArgs)
}

func TestRecursionConfigRejectedAtStartup(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "negative depth",
			args: []string{"--recursive", "--recursion-depth", "-1"},
			want: "recursion-depth",
		},
		{
			name: "negative max targets",
			args: []string{"--recursive", "--recursion-max-targets", "-1"},
			want: "recursion-max-targets",
		},
		{
			name: "recursion filters without recursive",
			args: []string{"--recursion-exclude-path", "admin"},
			want: "--recursive",
		},
		{
			name: "invalid exclude status",
			args: []string{"--recursive", "--recursion-exclude-status", "abc"},
			want: "recursion-exclude-status",
		},
		{
			name: "invalid glob",
			args: []string{"--recursive", "--recursion-exclude-path", "admin/["},
			want: "recursion-exclude-path",
		},
	}

	for _, x := range tt {
		t.Run(x.name, func(t *testing.T) {
			t.Parallel()

			err := runDirCommand(t, x.args...)
			if err == nil {
				t.Fatal("expected startup rejection")
			}
			if !strings.Contains(err.Error(), x.want) {
				t.Fatalf("error %q does not mention %q", err, x.want)
			}
			// Validation must happen before any request: the target is a port
			// that refuses connections, so a started run would report a
			// connection error instead.
			if strings.Contains(err.Error(), "connection refused") {
				t.Fatalf("run started before validation: %v", err)
			}
		})
	}
}

func TestRecursionStdinRejectedAtStartup(t *testing.T) {
	t.Parallel()

	app := &cli.App{
		Name:     "gobuster",
		Commands: []*cli.Command{Command()},
	}

	err := app.Run([]string{
		"gobuster", "dir",
		"-u", "http://127.0.0.1:1",
		"-w", "-",
		"--recursive",
		"--quiet",
	})
	if err == nil {
		t.Fatal("expected stdin recursion rejection")
	}
	if !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecursionDepthZeroIsValid(t *testing.T) {
	t.Parallel()

	// Depth 0 is the documented "do not expand" value and must pass startup
	// validation rather than being rejected as a missing value.
	opts := libgobuster.Options{RecursionDepth: 0}
	if err := opts.ValidateRecursionLimits(); err != nil {
		t.Fatalf("depth 0 must be valid: %v", err)
	}
}
