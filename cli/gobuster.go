package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/OJ/gobuster/v3/libgobuster"
)

const (
	ruler             = "==============================================================="
	cliProgressUpdate = 500 * time.Millisecond
)

// resultWorker outputs the results as they come in. This needs to be a range and should not handle
// the context so the channel always has a receiver and libgobuster will not block.
//
// In legacy mode results are streamed exactly as before. In stable mode every
// observation is handed to an Aggregator and the deterministic, deduplicated
// terminal output is rendered once the result channel is drained, so progress
// output can never interleave with the result stream.
func resultWorker(g *libgobuster.Gobuster, filename string, wg *sync.WaitGroup) {
	defer wg.Done()

	if !g.Opts.Stable {
		resultWorkerLegacy(g, filename)
		return
	}
	resultWorkerStable(g, filename)
}

func resultWorkerLegacy(g *libgobuster.Gobuster, filename string) {
	var f *os.File
	var err error
	if filename != "" {
		f, err = os.Create(filename)
		if err != nil {
			g.Logger.Fatalf("error on creating output file: %v", err)
		}
		defer f.Close()
	}

	for r := range g.Progress.ResultChan {
		s, err := r.ResultToString()
		if err != nil {
			g.Logger.Fatal(err)
		}
		if s != "" {
			s = strings.TrimSpace(s)
			if g.Opts.NoProgress || g.Opts.Quiet {
				_, _ = fmt.Printf("%s\n", s) // nolint forbidigo
			} else {
				// only print the clear line when progress output is enabled
				_, _ = fmt.Printf("%s%s\n", TerminalClearLine, s) // nolint forbidigo
			}
			if f != nil {
				err = writeToFile(f, s)
				if err != nil {
					g.Logger.Fatalf("error on writing output file: %v", err)
				}
			}
		}
	}
}

func resultWorkerStable(g *libgobuster.Gobuster, filename string) {
	aggregator := libgobuster.NewAggregator(g.Opts.StableChunkSize)

	for r := range g.Progress.ResultChan {
		normalized, ok := r.(libgobuster.NormalizedResult)
		if !ok {
			// a plugin without stable support must not silently drop data;
			// fall back to its legacy string on the result channel
			s, err := r.ResultToString()
			if err != nil {
				g.Logger.Fatal(err)
			}
			fmt.Print(s) // nolint forbidigo
			continue
		}
		if err := aggregator.Add(normalized.StableRecord()); err != nil {
			g.Logger.Fatal(err)
		}
	}

	iter, spilled, err := aggregator.Finalize()
	if err != nil {
		g.Logger.Fatal(err)
	}
	defer func() { _ = iter.Close() }()

	// render the whole terminal output into one buffer first so stdout and
	// the output file are byte identical and a write failure can never leave
	// a half line behind
	var buf bytes.Buffer
	unique, err := libgobuster.RenderStable(&buf, iter, g.Opts.OutputFormat, !g.Opts.NoChain)
	if err != nil {
		g.Logger.Fatal(err)
	}
	// capture the bytes before any sink consumes the buffer; both sinks must
	// emit exactly the same sequence
	data := buf.Bytes()

	if _, err := os.Stdout.Write(data); err != nil {
		// whatever was already written stays intact; report instead of dropping
		g.Logger.Fatalf("error on writing output: %v", err)
	}

	if filename != "" {
		if err := writeAllToFile(filename, data); err != nil {
			// preserve already written content and surface the failure loudly
			g.Logger.Errorf("error on writing output file: %v", err)
			g.Logger.Fatal(err)
		}
	}

	// statistics live on the log channel (stderr), never in the result stream
	stats := libgobuster.StatsReport{
		RequestsTotal:    g.Progress.RequestsIssued(),
		UniqueResults:    unique,
		FilteredStatus:   g.Progress.FilteredStatus(),
		FilteredLength:   g.Progress.FilteredLength(),
		FilteredWildcard: g.Progress.FilteredWildcard(),
		Errors:           g.Progress.ErrorsCount(),
		SpilledChunks:    spilled,
	}
	_ = libgobuster.RenderStats(os.Stderr, stats)
}

// writeAllToFile creates the output file and writes data in a single call per
// line boundary, syncing before close. On error the partially written file is
// kept and the error is returned.
func writeAllToFile(filename string, data []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("[!] Unable to create file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("[!] Unable to write to file %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("[!] Unable to sync file %w", err)
	}
	return nil
}

// errorWorker outputs the errors as they come in. This needs to be a range and should not handle
// the context so the channel always has a receiver and libgobuster will not block.
func errorWorker(g *libgobuster.Gobuster, wg *sync.WaitGroup) {
	defer wg.Done()

	for e := range g.Progress.ErrorChan {
		g.Progress.IncrementErrors()
		if !g.Opts.Quiet && !g.Opts.NoError {
			g.Logger.Error(e.Error())
			g.Logger.Debugf("%#v", e)
		}
	}
}

// messageWorker outputs messages as they come in. This needs to be a range and should not handle
// the context so the channel always has a receiver and libgobuster will not block.
func messageWorker(g *libgobuster.Gobuster, wg *sync.WaitGroup) {
	defer wg.Done()

	for msg := range g.Progress.MessageChan {
		if !g.Opts.Quiet {
			switch msg.Level {
			case libgobuster.LevelDebug:
				g.Logger.Debug(msg.Message)
			case libgobuster.LevelError:
				g.Logger.Error(msg.Message)
			case libgobuster.LevelWarn:
				g.Logger.Warn(msg.Message)
			case libgobuster.LevelInfo:
				g.Logger.Info(msg.Message)
			default:
				panic(fmt.Sprintf("invalid level %d", msg.Level))
			}
		}
	}
}

func printProgress(g *libgobuster.Gobuster) {
	requestsIssued := g.Progress.RequestsIssued()
	requestsExpected := g.Progress.RequestsExpected()
	if requestsExpected == 0 {
		requestsExpected = 1 // avoid division by zero
	}
	percent := float32(requestsIssued) * 100.0 / float32(requestsExpected)
	if math.IsNaN(float64(percent)) {
		percent = 0.0
	}
	s := fmt.Sprintf("%sProgress: %d / %d (%3.2f%%)", TerminalClearLine, requestsIssued, requestsExpected, percent)
	_, _ = fmt.Fprint(os.Stderr, s)
}

// progressWorker outputs the progress every tick. It will stop once cancel() is called
// on the context
func progressWorker(ctx context.Context, g *libgobuster.Gobuster, wg *sync.WaitGroup) {
	defer wg.Done()

	tick := time.NewTicker(cliProgressUpdate)

	for {
		select {
		case <-tick.C:
			printProgress(g)
		case <-ctx.Done():
			// print the final progress so we end at 100%
			printProgress(g)
			fmt.Println() // nolint:forbidigo
			return
		}
	}
}

func writeToFile(f *os.File, output string) error {
	_, err := fmt.Fprintf(f, "%s\n", output)
	if err != nil {
		return fmt.Errorf("[!] Unable to write to file %w", err)
	}
	return nil
}

// Gobuster is the main entry point for the CLI
func Gobuster(ctx context.Context, opts *libgobuster.Options, plugin libgobuster.GobusterPlugin, log *libgobuster.Logger) error {
	// Sanity checks
	if opts == nil {
		return errors.New("please provide valid options")
	}

	if plugin == nil {
		return errors.New("please provide valid plugin")
	}

	switch opts.OutputFormat {
	case "", libgobuster.OutputFormatText, libgobuster.OutputFormatTSV:
	default:
		return fmt.Errorf("invalid value for output-format %q", opts.OutputFormat)
	}
	// the machine parseable format implies the stable pipeline
	if opts.OutputFormat == libgobuster.OutputFormatTSV {
		opts.Stable = true
	}

	ctxCancel, cancel := context.WithCancel(ctx)
	defer cancel()

	gobuster, err := libgobuster.NewGobuster(opts, plugin, log)
	if err != nil {
		return err
	}

	if !opts.Quiet {
		log.Println(ruler)
		log.Printf("Gobuster v%s\n", libgobuster.VERSION)
		log.Println("by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)")
		log.Println(ruler)
		c, err := gobuster.GetConfigString()
		if err != nil {
			return fmt.Errorf("error on creating config string: %w", err)
		}
		log.Println(c)
		log.Println(ruler)
		gobuster.Logger.Printf("Starting gobuster in %s mode", plugin.Name())
		if opts.WordlistOffset > 0 {
			gobuster.Logger.Printf("Skipping the first %d elements...", opts.WordlistOffset)
		}
		log.Println(ruler)
	}

	fi, err := os.Stdout.Stat()
	if err != nil {
		return err
	}
	// check if we are not in a terminal. If so, disable output
	if (fi.Mode() & os.ModeCharDevice) != os.ModeCharDevice {
		opts.NoProgress = true
	}

	// our waitgroup for all goroutines
	// this ensures all goroutines are finished
	// when we call wg.Wait()
	var wg sync.WaitGroup

	wg.Add(1)
	go resultWorker(gobuster, opts.OutputFilename, &wg)

	wg.Add(1)
	go errorWorker(gobuster, &wg)

	wg.Add(1)
	go messageWorker(gobuster, &wg)

	if !opts.Quiet && !opts.NoProgress && !opts.Stable {
		// in stable mode the terminal output is rendered at the end, so a live
		// progress line would only create noise; progress counters still run
		wg.Add(1)
		go progressWorker(ctxCancel, gobuster, &wg)
	}

	err = gobuster.Run(ctxCancel)

	// call cancel func so progressWorker will exit (the only goroutine in this
	// file using the context) and to free resources
	cancel()
	// wait for all spun up goroutines to finish (all have to call wg.Done())
	wg.Wait()

	// Late error checking to finish all threads
	if err != nil {
		return err
	}

	if !opts.Quiet && !opts.Stable {
		log.Println(ruler)
		gobuster.Logger.Println("Finished")
		log.Println(ruler)
	}
	return nil
}
