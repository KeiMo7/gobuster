package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/OJ/gobuster/v3/libgobuster"
)

// Exit codes returned by the gobuster process
const (
	// ExitCodeHits is returned when the run finished and found at least one hit
	ExitCodeHits = 1
	// ExitCodeError is returned on any runtime error
	ExitCodeError = 2
)

// ExitError signals a specific process exit code without an error message
type ExitError struct {
	Code int
}

// Error implements the error interface
func (e *ExitError) Error() string {
	return fmt.Sprintf("exiting with code %d", e.Code)
}

const (
	ruler             = "==============================================================="
	cliProgressUpdate = 500 * time.Millisecond
)

// resultWorker outputs the results as they come in. This needs to be a range and should not handle
// the context so the channel always has a receiver and libgobuster will not block.
// It also counts the hits so the process exit code can distinguish hits from no hits.
func resultWorker(g *libgobuster.Gobuster, filename string, hitCounter *atomic.Int64, wg *sync.WaitGroup) {
	defer wg.Done()

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
			hitCounter.Add(1)
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

// structuredWorker appends results to the JSONL structured output file. On a
// write error it reports loudly, cancels the run and records the error so the
// process exits with an error code instead of silently dropping results.
func structuredWorker(g *libgobuster.Gobuster, w *libgobuster.StructuredWriter, cancel context.CancelFunc, writeErr *error, wg *sync.WaitGroup) {
	defer wg.Done()

	for r := range g.Progress.StructuredChan {
		if err := w.Write(r); err != nil {
			g.Logger.Errorf("error on writing structured output file: %v. Aborting the run.", err)
			if *writeErr == nil {
				*writeErr = err
			}
			cancel()
			// keep draining the channel so workers do not block
		}
	}
}

// rateControlFileContent is the schema of the runtime rate control file
type rateControlFileContent struct {
	GlobalRPS    *float64 `json:"global_rps"`
	PerTargetRPS *float64 `json:"per_target_rps"`
}

// rateControlWatcher polls the control file and applies rate changes at
// runtime. Every adjustment is logged with reason and timestamp.
func rateControlWatcher(ctx context.Context, g *libgobuster.Gobuster, filename string, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastMod time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		fi, err := os.Stat(filename)
		if err != nil {
			continue
		}
		if !fi.ModTime().After(lastMod) {
			continue
		}
		lastMod = fi.ModTime()

		content, err := os.ReadFile(filename)
		if err != nil {
			g.Logger.Warnf("could not read rate control file %s: %v", filename, err)
			continue
		}
		var parsed rateControlFileContent
		if err := json.Unmarshal(content, &parsed); err != nil {
			g.Logger.Warnf("could not parse rate control file %s: %v. Keeping current rates.", filename, err)
			continue
		}

		global := g.Opts.RateLimit
		if parsed.GlobalRPS != nil {
			global = *parsed.GlobalRPS
		}
		perTarget := g.Opts.RateLimitPerTarget
		if parsed.PerTargetRPS != nil {
			perTarget = *parsed.PerTargetRPS
		}
		g.Opts.RateLimiter.SetRates(global, perTarget, "rate control file updated")
	}
}

// errorWorker outputs the errors as they come in. This needs to be a range and should not handle
// the context so the channel always has a receiver and libgobuster will not block.
func errorWorker(g *libgobuster.Gobuster, wg *sync.WaitGroup) {
	defer wg.Done()

	for e := range g.Progress.ErrorChan {
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
		return errors.New("please provide a valid plugin")
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

	if opts.RateLimiter != nil {
		opts.RateLimiter.SetEventHandler(func(e libgobuster.RateAdjustEvent) {
			log.Infof("[RATE] %s", e.String())
		})
	}

	var structuredWriter *libgobuster.StructuredWriter
	if opts.OutputStructuredFilename != "" {
		var err error
		structuredWriter, err = libgobuster.NewStructuredWriter(opts.OutputStructuredFilename)
		if err != nil {
			return err
		}
		defer structuredWriter.Close()
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

	var hitCounter atomic.Int64
	wg.Add(1)
	go resultWorker(gobuster, opts.OutputFilename, &hitCounter, &wg)

	var structuredWriteErr error
	if structuredWriter != nil {
		wg.Add(1)
		go structuredWorker(gobuster, structuredWriter, cancel, &structuredWriteErr, &wg)
	}

	if opts.RateControlFile != "" && opts.RateLimiter != nil {
		wg.Add(1)
		go rateControlWatcher(ctxCancel, gobuster, opts.RateControlFile, &wg)
	}

	wg.Add(1)
	go errorWorker(gobuster, &wg)

	wg.Add(1)
	go messageWorker(gobuster, &wg)

	if !opts.Quiet && !opts.NoProgress {
		// if not quiet add a new workgroup entry and start the goroutine
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

	if structuredWriteErr != nil {
		return fmt.Errorf("error on writing structured output file: %w", structuredWriteErr)
	}

	if !opts.Quiet {
		log.Println(ruler)
		gobuster.Logger.Println("Finished")
		log.Println(ruler)
	}

	// distinguish hits from no hits in the process exit code
	if hitCounter.Load() > 0 {
		return &ExitError{Code: ExitCodeHits}
	}
	return nil
}
