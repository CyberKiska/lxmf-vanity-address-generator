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
	"os/signal"
	"runtime"
	"syscall"
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

func run(ctx context.Context, cfg config, stdout, stderr io.Writer) int {
	if err := execute(ctx, cfg, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func execute(ctx context.Context, cfg config, stdout, stderr io.Writer) error {
	writesOutput := !cfg.dryRun && cfg.benchmarkDuration == 0
	if err := validatePlatformOutputSecurity(runtime.GOOS, writesOutput, cfg.allowInheritedWinACL); err != nil {
		return err
	}
	var output *outputTarget
	if writesOutput {
		var err error
		output, err = openOutputTarget(cfg.outPath)
		if err != nil {
			return err
		}
		defer output.root.Close()
		if err := output.preflight(); err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			fmt.Fprintln(stderr, "Warning: inherited Windows ACL explicitly accepted; the output directory must already be restricted to your account.")
		}
	}

	var matcher addressMatcher
	if cfg.benchmarkDuration == 0 {
		var err error
		matcher, err = newAddressMatcher(cfg.prefix, cfg.postfix)
		if err != nil {
			return err
		}
	}

	if cfg.benchmarkDuration > 0 {
		fmt.Fprintln(stdout, "Benchmarking full LXMF identity generation...")
		fmt.Fprintf(stdout, "  Duration: %s\n", cfg.benchmarkDuration)
	} else {
		fmt.Fprintln(stdout, "Searching for LXMF vanity address...")
		if cfg.prefix != "" {
			fmt.Fprintf(stdout, "  Prefix:  %s\n", cfg.prefix)
		}
		if cfg.postfix != "" {
			fmt.Fprintf(stdout, "  Postfix: %s\n", cfg.postfix)
		}
		fmt.Fprintf(stdout, "  Expected attempts: %s (geometric expectation; not a deadline)\n", expectedAttempts(len(cfg.prefix)+len(cfg.postfix)))
	}
	fmt.Fprintf(stdout, "  Workers: %d\n", cfg.workers)
	if cfg.dryRun {
		fmt.Fprintln(stdout, "  Mode:    DRY RUN (matching private identity will not be saved)")
		fmt.Fprintln(stderr, "Warning: --dry-run does not save the matching private identity, so it cannot be recovered from program output; use --benchmark for performance measurement.")
	}
	fmt.Fprintln(stdout)

	searchContext, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	search := newSearcher(matcher, rand.Reader)
	search.stopOnMatch = cfg.benchmarkDuration == 0
	progressContext, stopProgress := context.WithCancel(ctx)
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		monitorProgress(progressContext, &search.attempts, stdout)
	}()

	runContext := searchContext
	stopBenchmark := func() {}
	startTime := time.Now()
	if cfg.benchmarkDuration > 0 {
		runContext, stopBenchmark = context.WithTimeout(searchContext, cfg.benchmarkDuration)
	}
	identity, err := search.run(runContext, cfg.workers)
	elapsed := time.Since(startTime)
	stopBenchmark()
	stopProgress()
	<-progressDone
	if cfg.benchmarkDuration > 0 {
		if errors.Is(err, context.DeadlineExceeded) {
			attempts := search.attempts.Load()
			avgRate := attemptsPerSecond(attempts, elapsed)
			fmt.Fprintf(stdout, "\nBenchmark complete: %s attempts in %s (%s/s average)\n", formatNumber(attempts), elapsed.Round(time.Microsecond), formatNumber(avgRate))
			return nil
		}
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("benchmark cancelled")
		}
		return err
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("search cancelled")
		}
		return err
	}
	defer wipeIdentitySecrets(&identity)

	// Persist the expensive result before writing success output to a pipe that
	// might have been closed by its reader.
	if !cfg.dryRun {
		if err := output.saveIdentity(&identity, cfg.includePrivateExports); err != nil {
			return err
		}
	}
	addrHex := hex.EncodeToString(identity.Address[:])
	fmt.Fprintf(stdout, "\n✓ Found matching address: %s\n", addrHex)
	fmt.Fprintf(stdout, "  Total attempts: %d\n", search.attempts.Load())

	if cfg.dryRun {
		return nil
	}

	fmt.Fprintf(stdout, "  Saved to: %s\n", cfg.outPath)
	if cfg.includePrivateExports {
		fmt.Fprintf(stderr, "Warning: %s contains reversible private-key exports and must be protected like the identity file.\n", cfg.outPath+".txt")
	}
	return nil
}
