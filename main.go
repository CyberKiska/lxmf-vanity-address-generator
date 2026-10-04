package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments %q; all options must use flags", flag.Args())
	}

	prefix = strings.ToLower(prefix)
	postfix = strings.ToLower(postfix)

	if err := validateInputs(); err != nil {
		return err
	}
	writesOutput := !dryRun && benchmarkDuration == 0
	if err := validatePlatformOutputSecurity(runtime.GOOS, writesOutput, allowInheritedWinACL); err != nil {
		return err
	}
	var output *outputTarget
	if writesOutput {
		var err error
		output, err = openOutputTarget(outPath)
		if err != nil {
			return err
		}
		defer output.root.Close()
		if err := output.preflight(); err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			fmt.Fprintln(os.Stderr, "Warning: inherited Windows ACL explicitly accepted; the output directory must already be restricted to your account.")
		}
	}

	var matcher addressMatcher
	if benchmarkDuration == 0 {
		var err error
		matcher, err = newAddressMatcher(prefix, postfix)
		if err != nil {
			return err
		}
	}

	if benchmarkDuration > 0 {
		fmt.Println("Benchmarking full LXMF identity generation...")
		fmt.Printf("  Duration: %s\n", benchmarkDuration)
	} else {
		fmt.Println("Searching for LXMF vanity address...")
		if prefix != "" {
			fmt.Printf("  Prefix:  %s\n", prefix)
		}
		if postfix != "" {
			fmt.Printf("  Postfix: %s\n", postfix)
		}
		fmt.Printf("  Expected attempts: %s (geometric expectation; not a deadline)\n", expectedAttempts(len(prefix)+len(postfix)))
	}
	fmt.Printf("  Workers: %d\n", workers)
	if dryRun {
		fmt.Println("  Mode:    DRY RUN (matching private identity will not be saved)")
		fmt.Fprintln(os.Stderr, "Warning: --dry-run does not save the matching private identity, so it cannot be recovered from program output; use --benchmark for performance measurement.")
	}
	fmt.Println()

	searchContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	search := newSearcher(matcher, rand.Reader)
	search.stopOnMatch = benchmarkDuration == 0
	progressContext, stopProgress := context.WithCancel(context.Background())
	progressDone := make(chan struct{})
	go func() {
		defer close(progressDone)
		monitorProgress(progressContext, &search.attempts)
	}()

	runContext := searchContext
	stopBenchmark := func() {}
	startTime := time.Now()
	if benchmarkDuration > 0 {
		runContext, stopBenchmark = context.WithTimeout(searchContext, benchmarkDuration)
	}
	identity, err := search.run(runContext, workers)
	elapsed := time.Since(startTime)
	stopBenchmark()
	stopProgress()
	<-progressDone
	if benchmarkDuration > 0 {
		if errors.Is(err, context.DeadlineExceeded) {
			attempts := search.attempts.Load()
			avgRate := attemptsPerSecond(attempts, elapsed)
			fmt.Printf("\nBenchmark complete: %s attempts in %s (%s/s average)\n", formatNumber(attempts), elapsed.Round(time.Microsecond), formatNumber(avgRate))
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
	if !dryRun {
		if err := output.saveIdentity(&identity, includePrivateExports); err != nil {
			return err
		}
	}
	addrHex := hex.EncodeToString(identity.Address[:])
	fmt.Printf("\n✓ Found matching address: %s\n", addrHex)
	fmt.Printf("  Total attempts: %d\n", search.attempts.Load())

	if dryRun {
		return nil
	}

	fmt.Printf("  Saved to: %s\n", outPath)
	if includePrivateExports {
		fmt.Fprintf(os.Stderr, "Warning: %s contains reversible private-key exports and must be protected like the identity file.\n", outPath+".txt")
	}
	return nil
}
