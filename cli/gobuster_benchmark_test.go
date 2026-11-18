package cli

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/OJ/gobuster/v3/libgobuster"
)

type benchmarkPlugin struct{}

func (benchmarkPlugin) Name() string {
	return "benchmark"
}

func (benchmarkPlugin) PreRun(context.Context, *libgobuster.Progress) error {
	return nil
}

func (benchmarkPlugin) ProcessWord(context.Context, string, *libgobuster.Progress) (libgobuster.Result, error) {
	return benchmarkResult{}, nil
}

func (benchmarkPlugin) AdditionalWords(string) []string {
	return nil
}

func (benchmarkPlugin) AdditionalWordsLen() int {
	return 0
}

func (benchmarkPlugin) AdditionalSuccessWords(string) []string {
	return nil
}

func (benchmarkPlugin) GetConfigString() (string, error) {
	return "", nil
}

type benchmarkResult struct{}

func (benchmarkResult) ResultToString() (string, error) {
	return "result", nil
}

func BenchmarkGobusterDefaultOutput(b *testing.B) {
	wordlist, err := os.CreateTemp(b.TempDir(), "words-*")
	if err != nil {
		b.Fatalf("could not create wordlist: %v", err)
	}
	for i := range 1000 {
		if _, err := fmt.Fprintf(wordlist, "word-%d\n", i); err != nil {
			b.Fatalf("could not write wordlist: %v", err)
		}
	}
	if err := wordlist.Close(); err != nil {
		b.Fatalf("could not close wordlist: %v", err)
	}

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatalf("could not open devnull: %v", err)
	}
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		_ = devnull.Close()
	}()
	os.Stdout = devnull
	os.Stderr = devnull

	opts := libgobuster.Options{
		Threads:    10,
		Wordlist:   wordlist.Name(),
		Quiet:      true,
		NoProgress: true,
	}
	logger := libgobuster.NewLogger(false)

	b.ReportAllocs()
	for b.Loop() {
		if err := Gobuster(context.Background(), &opts, benchmarkPlugin{}, logger); err != nil {
			b.Fatalf("gobuster failed: %v", err)
		}
	}
}
