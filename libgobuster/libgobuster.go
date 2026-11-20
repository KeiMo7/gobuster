package libgobuster

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// PATTERN is the pattern for wordlist replacements in pattern file
const PATTERN = "{GOBUSTER}"

// SetupFunc is the "setup" function prototype for implementations
type SetupFunc func(*Gobuster) error

// ProcessFunc is the "process" function prototype for implementations
type ProcessFunc func(*Gobuster, string) ([]Result, error)

// ResultToStringFunc is the "to string" function prototype for implementations
type ResultToStringFunc func(*Gobuster, *Result) (*string, error)

// Gobuster is the main object when creating a new run
type Gobuster struct {
	Opts     *Options
	Logger   *Logger
	plugin   GobusterPlugin
	Progress *Progress
}

type Guess struct {
	word              string
	discoverOnSuccess bool
}

type successfulGuess struct {
	guess  *Guess
	result Result
}

type Wordlist struct {
	scanner        *bufio.Scanner
	guessesPerLine int
	isStream       bool
}

// NewGobuster returns a new Gobuster object
func NewGobuster(opts *Options, plugin GobusterPlugin, logger *Logger) (*Gobuster, error) {
	var g Gobuster
	g.Opts = opts
	g.plugin = plugin
	g.Logger = logger
	g.Progress = NewProgress()

	return &g, nil
}

func (g *Gobuster) worker(ctx context.Context, guessChan <-chan *Guess, successChan chan<- successfulGuess, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		// Prioritize stopping when the context is done
		select {
		case <-ctx.Done():
			return
		default:
		}
		select {
		case <-ctx.Done():
			return
		case guess := <-guessChan:

			// Mode-specific processing
			res, err := g.plugin.ProcessWord(ctx, guess.word, g.Progress)
			if err != nil {
				// do not exit and continue
				g.Progress.ErrorChan <- fmt.Errorf("error on word %s: %w", guess.word, err)
			}

			if res != nil {
				if !isSuppressedResult(res) {
					g.Progress.ResultChan <- res
				}

				select {
				case <-ctx.Done():
					g.Progress.incrementRequests()
					return
				case successChan <- successfulGuess{guess: guess, result: res}:
				}
			}

			g.Progress.incrementRequests()

			select {
			case <-ctx.Done():
			case <-time.After(g.Opts.Delay):
			}
		}
	}
}

// isSuppressedResult reports whether a result should seed a recursive scan but
// not be written to the normal result output.
func isSuppressedResult(res Result) bool {
	suppressed, ok := res.(SuppressedResult)
	return ok && suppressed.SuppressResult()
}

func feed(ctx context.Context, guessChan chan<- *Guess, words []string, discoverOnSuccess bool) {
	for _, w := range words {
		guess := &Guess{word: w, discoverOnSuccess: discoverOnSuccess}
		// Prioritize stopping when the context is done
		select {
		case <-ctx.Done():
			return
		default:
		}
		select {
		// need to check here too otherwise guessChan will block
		case <-ctx.Done():
			return
		case guessChan <- guess:
		}
	}
}

func (g *Gobuster) feeder(ctx context.Context, guessChan chan<- *Guess, words []string, discoverOnSuccess bool, wg *sync.WaitGroup) {
	defer wg.Done()

	feed(ctx, guessChan, words, discoverOnSuccess)
}

func (g *Gobuster) feedWordlist(ctx context.Context, guessChan chan<- *Guess, wordlist *Wordlist, wg *sync.WaitGroup) {
	defer wg.Done()

	for wordlist.scanner.Scan() {
		// Prioritize stopping when the context is done
		select {
		case <-ctx.Done():
			return
		default:
		}

		word := strings.TrimSpace(wordlist.scanner.Text())

		switch {
		case wordlist.isStream && len(word) != 0:
			// Increment to keep track of expected work
			g.Progress.IncrementTotalRequests(wordlist.guessesPerLine)
		case wordlist.isStream && len(word) == 0:
			// Skip empty lines without incrementing
			continue
		case len(word) == 0:
			// Skip empty lines removing expected work
			g.Progress.IncrementTotalRequests(-1 * wordlist.guessesPerLine)
			continue
		}

		if len(g.Opts.Patterns) > 0 {
			for _, w := range g.processPatterns(word) {
				guess := &Guess{word: w, discoverOnSuccess: true}
				select {
				case <-ctx.Done():
					return
				case guessChan <- guess:
				}

				feed(ctx, guessChan, g.plugin.AdditionalWords(w), true)
			}
		} else {
			guess := &Guess{word: word, discoverOnSuccess: true}

			select {
			case <-ctx.Done():
				return
			case guessChan <- guess:
			}

			feed(ctx, guessChan, g.plugin.AdditionalWords(word), true)
		}
	}
}

func (g *Gobuster) getWordlist(wordlist io.ReadSeeker) (*Wordlist, error) {
	// calculate expected requests
	guessesPerLine := g.guessesPerLine()

	if g.Opts.Wordlist == "-" {
		// Read directly from stdin
		return &Wordlist{scanner: bufio.NewScanner(os.Stdin), guessesPerLine: guessesPerLine, isStream: true}, nil
	}

	lines, err := lineCounter(wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of lines: %w", err)
	}

	if lines-g.Opts.WordlistOffset <= 0 {
		return nil, errors.New("offset is greater than the number of lines in the wordlist")
	}

	g.Progress.IncrementTotalRequests(lines * guessesPerLine)

	// add offset if needed (offset defaults to 0)
	g.Progress.incrementRequestsIssues(g.Opts.WordlistOffset * guessesPerLine)

	// rewind wordlist after lineCounter
	_, err = wordlist.Seek(0, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to rewind wordlist: %w", err)
	}

	wordlistScanner := bufio.NewScanner(wordlist)

	// skip lines
	for range g.Opts.WordlistOffset {
		if !wordlistScanner.Scan() {
			if err := wordlistScanner.Err(); err != nil {
				return nil, fmt.Errorf("failed to skip lines in wordlist: %w", err)
			}
			return nil, errors.New("failed to skip lines in wordlist")
		}
	}

	return &Wordlist{scanner: wordlistScanner, guessesPerLine: guessesPerLine, isStream: false}, nil
}

// guessesPerLine is the number of requests a single non-empty wordlist line
// produces, including pattern and extension expansion.
func (g *Gobuster) guessesPerLine() int {
	if len(g.Opts.Patterns) > 0 {
		nPats := len(g.Opts.Patterns)
		return nPats + nPats*g.plugin.AdditionalWordsLen()
	}
	return 1 + g.plugin.AdditionalWordsLen()
}

// Run the busting of the website with the given
// set of settings from the command line.
func (g *Gobuster) Run(ctx context.Context) error {
	defer close(g.Progress.ResultChan)
	defer close(g.Progress.ErrorChan)
	defer close(g.Progress.MessageChan)

	if !g.Opts.Recursion {
		return g.runSingle(ctx)
	}

	return g.runRecursive(ctx)
}

// runSingle performs one complete wordlist pass over the plugin's base URL.
// This is the original, non-recursive behaviour and must stay unchanged.
func (g *Gobuster) runSingle(ctx context.Context) error {
	if err := g.plugin.PreRun(ctx, g.Progress); err != nil {
		return err
	}

	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()
	feederCtx, feederCancel := context.WithCancel(ctx)
	defer feederCancel()

	var workerGroup, feederGroup sync.WaitGroup
	workerGroup.Add(g.Opts.Threads)

	guessChan := make(chan *Guess, g.Opts.Threads*3)
	successChan := make(chan successfulGuess)

	var f io.ReadSeekCloser
	if g.Opts.Wordlist != "-" { // stdin case is handled inside getWordlist
		var err error
		f, err = os.Open(g.Opts.Wordlist)
		if err != nil {
			return fmt.Errorf("failed to open wordlist: %w", err)
		}
		defer f.Close()
	}

	wordlist, err := g.getWordlist(f)
	if err != nil {
		return err
	}

	// Create goroutines for each of the number of threads
	// specified.
	for range g.Opts.Threads {
		go g.worker(workerCtx, guessChan, successChan, &workerGroup)
	}

	feederGroup.Add(1)
	go g.feedWordlist(feederCtx, guessChan, wordlist, &feederGroup)

ListenForMore:
	for {
		// Prioritize stopping when the context is done
		select {
		case <-ctx.Done():
			break ListenForMore
		default:
		}

		select {
		case <-ctx.Done():
			break ListenForMore
		case successGuess := <-successChan:
			// Add more guesses based on the results of previous attempts
			if successGuess.guess.discoverOnSuccess {
				discoverWords := g.plugin.AdditionalSuccessWords(successGuess.guess.word)
				if len(discoverWords) > 0 {
					g.Progress.IncrementTotalRequests(len(discoverWords))
					feederGroup.Add(1)
					go g.feeder(feederCtx, guessChan, discoverWords, false, &feederGroup)
				}

				patternDiscoverWords := g.processDiscoverPatterns(successGuess.guess.word)
				if len(patternDiscoverWords) > 0 {
					g.Progress.IncrementTotalRequests(len(patternDiscoverWords))
					feederGroup.Add(1)
					go g.feeder(feederCtx, guessChan, patternDiscoverWords, false, &feederGroup)
				}
			}
		case <-time.After(200 * time.Millisecond):
			// With requests issued only after the results are synchronously
			// reported, this is well ordered without the timeout, however it would
			// exert a lot of lock pressure during the run to keep doing this in a
			// hot loop
			if g.Progress.RequestsExpected() == g.Progress.RequestsIssued() {
				// All the expected requests have completed, there is no pending or
				// in-progress work. If moreWordsChan was buffered we would need to
				// check it again here to ensure no pending work was added while we
				// acquired the locks
				break ListenForMore
			}
		}
	}

	feederCancel()
	workerCancel()
	feederGroup.Wait()
	workerGroup.Wait()

	if err := wordlist.scanner.Err(); err != nil {
		return err
	}

	return nil
}

// runRecursive expands every discovered directory with the same wordlist,
// bounded by the configured depth and visited-target limits.
//
// Each directory is a separate "layer". A layer starts its own workers and
// wordlist feeder, but reuses the configured thread count and delay, so the
// concurrency never exceeds the configured amount. Results discovered during a
// layer are queued only after the layer has fully drained, which guarantees
// that the end-of-layer decision sees every dynamic addition.
func (g *Gobuster) runRecursive(ctx context.Context) error {
	plugin, ok := g.plugin.(RecursivePlugin)
	if !ok {
		return errors.New("the selected plugin does not support recursion")
	}
	if g.Opts.Wordlist == "-" {
		// Recursion has to replay the wordlist for every discovered directory,
		// which is impossible for a stream of unknown length without buffering
		// it entirely. Reject it up front instead of silently scanning only the
		// base URL.
		return errors.New("recursion is not supported when the wordlist is read from stdin")
	}
	if err := g.Opts.ValidateRecursionLimits(); err != nil {
		return err
	}

	words, err := readWordlistWords(g.Opts.Wordlist, g.Opts.WordlistOffset)
	if err != nil {
		return err
	}
	if len(words) == 0 && g.Opts.WordlistOffset > 0 {
		return errors.New("offset is greater than the number of lines in the wordlist")
	}

	// Every layer replays exactly the same non-empty words, so the expected
	// count per layer matches the guesses that will actually be fed. Blank
	// lines produce no work and are therefore not counted, mirroring the
	// decrement the single-layer feeder performs for them.
	guessesPerLine := g.guessesPerLine()
	requestsPerLayer := len(words) * guessesPerLine

	state := newRecursionState(g.Opts.RecursionDepth, g.Opts.RecursionMaxTargets)
	root := plugin.RootTarget()
	state.seed(root)

	if err := g.plugin.PreRun(ctx, g.Progress); err != nil {
		return err
	}

	first := true
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		if !first {
			current, ok := state.pop()
			if !ok {
				break
			}
			if err := plugin.SetTarget(current.url); err != nil {
				g.Progress.ErrorChan <- fmt.Errorf("skipping recursive target %s: %w", current.url, err)
				continue
			}
			state.depth = current.depth
			if err := g.plugin.PreRun(ctx, g.Progress); err != nil {
				// A failing branch must not abort the whole run: report the
				// error and keep expanding the other queued directories.
				g.Progress.ErrorChan <- fmt.Errorf("precheck failed for %s: %w", current.url, err)
				continue
			}
			state.expandedDirs++
		}
		first = false

		// Register the work for this layer before any request is issued so
		// the progress numerator and denominator stay consistent.
		g.Progress.IncrementTotalRequests(requestsPerLayer)

		if err := g.runLayer(ctx, words, state); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}

	if state.truncated {
		g.Progress.MessageChan <- Message{
			Level:   LevelWarn,
			Message: fmt.Sprintf("recursive scan truncated: visited directory limit of %d reached, not all discovered directories were expanded", g.Opts.RecursionMaxTargets),
		}
	}

	g.Progress.MessageChan <- Message{
		Level:   LevelInfo,
		Message: fmt.Sprintf("recursive scan finished: %d director%s expanded (depth limit %d)", state.expandedDirs+1, plural(state.expandedDirs+1), g.Opts.RecursionDepth),
	}

	return nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// runLayer runs the wordlist once against the plugin's current target. It
// returns after all workers and feeders for this layer have stopped, so all
// results of the layer have been observed by the caller.
func (g *Gobuster) runLayer(ctx context.Context, words []string, state *recursionState) error {
	layerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var workerGroup, feederGroup sync.WaitGroup
	workerGroup.Add(g.Opts.Threads)

	guessChan := make(chan *Guess, g.Opts.Threads*3)
	successChan := make(chan successfulGuess)

	for range g.Opts.Threads {
		go g.worker(layerCtx, guessChan, successChan, &workerGroup)
	}

	feedDone := make(chan struct{})
	feederGroup.Add(1)
	go func() {
		defer feederGroup.Done()
		defer close(feedDone)
		g.feedWords(layerCtx, guessChan, words)
	}()

ListenForLayerEnd:
	for {
		select {
		case <-ctx.Done():
			break ListenForLayerEnd
		case success := <-successChan:
			if _, truncated := state.considerResult(success.result); truncated {
				state.truncated = true
			}

			if success.guess.discoverOnSuccess {
				discoverWords := g.plugin.AdditionalSuccessWords(success.guess.word)
				if len(discoverWords) > 0 {
					g.Progress.IncrementTotalRequests(len(discoverWords))
					feederGroup.Add(1)
					go g.feeder(layerCtx, guessChan, discoverWords, false, &feederGroup)
				}

				patternDiscoverWords := g.processDiscoverPatterns(success.guess.word)
				if len(patternDiscoverWords) > 0 {
					g.Progress.IncrementTotalRequests(len(patternDiscoverWords))
					feederGroup.Add(1)
					go g.feeder(layerCtx, guessChan, patternDiscoverWords, false, &feederGroup)
				}
			}
		case <-time.After(200 * time.Millisecond):
			// The whole layer's expected work is registered before it starts
			// (and every dynamic addition is registered before it is fed), so
			// equality can only be observed once the feeder has produced all
			// guesses and every worker has reported its result.
			select {
			case <-feedDone:
			default:
				continue
			}
			if g.Progress.RequestsExpected() == g.Progress.RequestsIssued() {
				break ListenForLayerEnd
			}
		}
	}

	cancel()
	feederGroup.Wait()
	workerGroup.Wait()
	return nil
}

// feedWords feeds a fixed list of words. It mirrors feedWordlist but does not
// own expected-request accounting because the recursive scheduler registers a
// layer's total up front.
func (g *Gobuster) feedWords(ctx context.Context, guessChan chan<- *Guess, words []string) {
	for _, word := range words {
		if len(g.Opts.Patterns) > 0 {
			for _, w := range g.processPatterns(word) {
				if !sendGuess(ctx, guessChan, &Guess{word: w, discoverOnSuccess: true}) {
					return
				}
				feed(ctx, guessChan, g.plugin.AdditionalWords(w), true)
			}
			continue
		}

		if !sendGuess(ctx, guessChan, &Guess{word: word, discoverOnSuccess: true}) {
			return
		}
		feed(ctx, guessChan, g.plugin.AdditionalWords(word), true)
	}
}

func sendGuess(ctx context.Context, guessChan chan<- *Guess, guess *Guess) bool {
	select {
	case <-ctx.Done():
		return false
	case guessChan <- guess:
		return true
	}
}

// readWordlistWords loads every non-empty word after skipping the first
// `offset` physical lines, mirroring the offset handling of the single-layer
// reader. The same list is replayed for each recursive layer.
func readWordlistWords(filename string, offset int) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	words := make([]string, 0)
	line := 0
	for scanner.Scan() {
		line++
		if line <= offset {
			continue
		}
		word := strings.TrimSpace(scanner.Text())
		if len(word) == 0 {
			continue
		}
		words = append(words, word)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read wordlist: %w", err)
	}
	return words, nil
}

// GetConfigString returns the current config as a printable string
func (g *Gobuster) GetConfigString() (string, error) {
	return g.plugin.GetConfigString()
}

func (g *Gobuster) processPatterns(word string) []string {
	if g.Opts.PatternFile == "" {
		return nil
	}

	return g.applyPatterns(word, g.Opts.Patterns)
}

func (g *Gobuster) processDiscoverPatterns(word string) []string {
	if g.Opts.DiscoverPatternFile == "" {
		return nil
	}

	return g.applyPatterns(word, g.Opts.DiscoverPatterns)
}

func (g *Gobuster) applyPatterns(word string, patterns []string) []string {
	pat := make([]string, len(patterns))
	for i, x := range patterns {
		pat[i] = strings.ReplaceAll(x, PATTERN, word)
	}
	return pat
}
