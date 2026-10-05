package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

func main() {
	cfg, err := parseArgs(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	os.Exit(run(context.Background(), cfg, os.Stdout, os.Stderr))
}

// Tests use explicit dependencies, never package-level randomness overrides.
type runDependencies struct {
	rng            io.Reader
	openTarget     func(string) (*outputTarget, error)
	signals        <-chan os.Signal
	consoleTimeout time.Duration
}

func run(ctx context.Context, cfg config, stdout, stderr io.Writer) int {
	return runWithDependencies(ctx, cfg, stdout, stderr, runDependencies{})
}
func runWithDependencies(ctx context.Context, cfg config, stdout, stderr io.Writer, deps runDependencies) int {
	searchCtx, cancelSearch := context.WithCancel(ctx)
	defer cancelSearch()
	input := deps.signals
	if input == nil {
		signals, stop := processSignals()
		defer stop()
		input = signals
	}
	signals := newSignalOwner(input, cancelSearch)
	defer signals.close()
	c := newConsole(stderr)
	closeTimeout := deps.consoleTimeout
	if closeTimeout == 0 {
		closeTimeout = 2 * time.Second
	}
	defer c.close(closeTimeout)
	fail := func(err error) int { c.status("Error: %v\n", err); return 1 }
	if err := selfTest(knownAnswerIdentity()); err != nil {
		return fail(err)
	}
	writesOutput := !cfg.dryRun && cfg.benchmarkDuration == 0
	if err := validatePlatformOutputSecurity(runtime.GOOS, writesOutput, cfg.allowInheritedWinACL); err != nil {
		return fail(err)
	}
	var output, fallback *outputTarget
	if writesOutput {
		open := deps.openTarget
		if open == nil {
			open = openOutputTarget
		}
		var err error
		output, err = open(cfg.outPath)
		if err != nil {
			return fail(err)
		}
		defer output.root.Close()
		if err := output.preflight(); err != nil {
			return fail(err)
		}
	}
	if writesOutput && cfg.fallbackOut != "" {
		open := deps.openTarget
		if open == nil {
			open = openOutputTarget
		}
		var err error
		fallback, err = open(cfg.fallbackOut)
		if err != nil {
			return fail(err)
		}
		defer fallback.root.Close()
		if targetsOverlap(output, fallback) {
			return fail(fmt.Errorf("primary and fallback identity/sidecar paths overlap"))
		}
		if err := fallback.preflight(); err != nil {
			return fail(err)
		}
	}

	var matcher addressMatcher
	if cfg.benchmarkDuration == 0 {
		var err error
		matcher, err = newAddressMatcher(cfg.prefix, cfg.postfix)
		if err != nil {
			return fail(err)
		}
	}
	c.status("LXMF vanity search: prefix=%q postfix=%q workers=%d\n", cfg.prefix, cfg.postfix, cfg.workers)
	if cfg.benchmarkDuration == 0 {
		c.status("Expected attempts: %s (geometric expectation; not a deadline)\n", expectedAttempts(len(cfg.prefix)+len(cfg.postfix)))
	}
	if len(cfg.prefix)+len(cfg.postfix) > 8 && cfg.fallbackOut == "" && writesOutput {
		c.status("For expensive searches, configure --fallback-out in another protected directory.\n")
	}
	if cfg.dryRun {
		c.status("Warning: --dry-run discards the matching private identity.\n")
	}
	search := newSearcher(matcher, rand.Reader)
	if deps.rng != nil {
		search.rng = deps.rng
	}
	search.stopOnMatch = cfg.benchmarkDuration == 0
	search.maxAttempts = cfg.maxAttempts
	progressCtx, stopProgress := context.WithCancel(searchCtx)
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		monitorProgress(progressCtx, &search.attempts, c, isCharacterDevice(stderr))
	}()
	runCtx := searchCtx
	stopTimer := func() {}
	if cfg.benchmarkDuration > 0 {
		runCtx, stopTimer = context.WithTimeout(searchCtx, cfg.benchmarkDuration)
	} else if cfg.timeout > 0 {
		runCtx, stopTimer = context.WithTimeout(searchCtx, cfg.timeout)
	}
	c.status("search started\n")
	start := time.Now()
	var identity Identity
	err := search.run(runCtx, cfg.workers, &identity)
	elapsed := time.Since(start)
	stopTimer()
	stopProgress()
	// Progress only queues messages, so joining it never waits for a console write.
	<-progressDone
	signals.phase("save")
	var result saveResult
	exitCode := 0
	if err == nil && !cfg.dryRun && cfg.benchmarkDuration == 0 {
		round := func() saveResult {
			primary := output.saveIdentity(&identity, matcher, cfg.includePrivateExports)
			if primary.saved() || primary.internal || fallback == nil {
				return primary
			}
			other := fallback.saveIdentity(&identity, matcher, cfg.includePrivateExports)
			other.Unverified = append(other.Unverified, primary.Unverified...)
			other.Deviations = append(other.Deviations, primary.Deviations...)
			if other.saved() {
				other.Deviations = appendUnique(other.Deviations, "saved at the preflighted fallback target")
			}
			return other
		}
		var abandoned bool
		result, abandoned = recoverWinner(round, signals.recovery, cfg.saveRetryTimeout, c, func() { signals.phase("recovery") })
		if abandoned {
			exitCode = 130
		}
		if !result.saved() && !abandoned {
			exitCode = 1
		} else if len(result.Deviations) > 0 || len(result.Unverified) > 0 {
			exitCode = 3
		}
	}
	if search.workerWarning != nil && err == nil {
		result.Deviations = appendUnique(result.Deviations, search.workerWarning.Error())
		if result.saved() {
			exitCode = 3
		}
	}
	// Construct only public output, then clear the winner before any final write.
	var text string
	if cfg.benchmarkDuration > 0 && errors.Is(err, context.DeadlineExceeded) {
		text = fmt.Sprintf("Benchmark complete: %s attempts in %s (%s/s average)\n", formatNumber(search.attempts.Load()), elapsed.Round(time.Microsecond), formatNumber(attemptsPerSecond(search.attempts.Load(), elapsed)))
	} else if err != nil {
		exitCode = 1
		if errors.Is(err, context.Canceled) {
			exitCode = 130
		} else if errors.Is(err, errAttemptLimit) || errors.Is(err, context.DeadlineExceeded) {
			exitCode = 4
		}
		text = fmt.Sprintf("Search failed: %v\n", err)
	} else {
		text = fmt.Sprintf("Found matching address: %s\n  Total attempts: %d\n", hex.EncodeToString(identity.Address[:]), search.attempts.Load())
		for _, path := range result.Verified {
			text += fmt.Sprintf("  Saved and verified: %s\n", path)
		}
		for _, path := range result.Unverified {
			text += fmt.Sprintf("  Unverified retained file: %s\n", path)
		}
		for _, warning := range result.Deviations {
			text += fmt.Sprintf("  Warning: %s\n", warning)
		}
		if !cfg.dryRun && !result.saved() {
			text += fmt.Sprintf("  Identity not verified saved: %v\n", result.cause)
		}
	}
	wipeIdentitySecrets(&identity)
	c.close(closeTimeout)
	n, writeErr := io.WriteString(stdout, text)
	if writeErr != nil || n != len(text) {
		if result.saved() {
			return 3
		}
		return 1
	}
	return exitCode
}
func isCharacterDevice(writer io.Writer) bool {
	f, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
