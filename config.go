package main

import (
	"flag"
	"fmt"
	"runtime"
	"time"
)

var (
	prefix                string
	postfix               string
	workers               int
	outPath               string
	dryRun                bool
	includePrivateExports bool
	benchmarkDuration     time.Duration
	allowInheritedWinACL  bool
)

func init() {
	flag.StringVar(&prefix, "prefix", "", "Desired hex prefix (1-32 chars)")
	flag.StringVar(&postfix, "postfix", "", "Desired hex postfix/suffix (1-32 chars)")
	flag.IntVar(&workers, "workers", defaultWorkerCount(), "Number of parallel workers")
	flag.StringVar(&outPath, "out", "identity", "Output path for identity file")
	flag.BoolVar(&dryRun, "dry-run", false, "Find a match but do not save it")
	flag.BoolVar(&includePrivateExports, "include-private-exports", false, "Include reversible private-key exports in <out>.txt (sensitive)")
	flag.DurationVar(&benchmarkDuration, "benchmark", 0, "Benchmark full identity generation for a duration (for example 30s); no identity is selected or saved")
	flag.BoolVar(&allowInheritedWinACL, "allow-inherited-windows-acl", false, "On Windows, explicitly accept the output directory's inherited ACL for private files")
}

func defaultWorkerCount() int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 1 {
		return 1
	}
	if workers > maxWorkerCount {
		return maxWorkerCount
	}
	return workers
}

func validateInputs() error {
	if benchmarkDuration < 0 {
		return fmt.Errorf("benchmark duration must not be negative")
	}
	if benchmarkDuration > 0 {
		if prefix != "" || postfix != "" {
			return fmt.Errorf("--benchmark cannot be combined with --prefix or --postfix")
		}
		if dryRun {
			return fmt.Errorf("--benchmark cannot be combined with --dry-run")
		}
		if includePrivateExports {
			return fmt.Errorf("--benchmark cannot be combined with --include-private-exports")
		}
	} else {
		if err := validatePatterns(prefix, postfix); err != nil {
			return err
		}
	}
	if workers < 1 {
		return fmt.Errorf("workers must be at least 1")
	}
	if workers > maxWorkerCount {
		return fmt.Errorf("workers must not exceed %d", maxWorkerCount)
	}
	if dryRun && includePrivateExports {
		return fmt.Errorf("--include-private-exports cannot be used with --dry-run")
	}
	return nil
}

func validatePlatformOutputSecurity(goos string, writesOutput, allowInheritedACL bool) error {
	if goos != "windows" {
		if allowInheritedACL {
			return fmt.Errorf("--allow-inherited-windows-acl is only valid on Windows")
		}
		return nil
	}
	if writesOutput && !allowInheritedACL {
		return fmt.Errorf("refusing to write a private identity with an unverified inherited Windows ACL; secure the output directory, then explicitly pass --allow-inherited-windows-acl")
	}
	return nil
}

func validatePatterns(prefix, postfix string) error {
	if prefix == "" && postfix == "" {
		return fmt.Errorf("at least one of --prefix or --postfix must be specified")
	}
	if len(prefix) > addressHexLength {
		return fmt.Errorf("prefix must be 1-32 hex characters")
	}
	if len(postfix) > addressHexLength {
		return fmt.Errorf("postfix must be 1-32 hex characters")
	}
	if !isHex(prefix) {
		return fmt.Errorf("prefix must contain only hex characters [0-9a-fA-F]")
	}
	if !isHex(postfix) {
		return fmt.Errorf("postfix must contain only hex characters [0-9a-fA-F]")
	}
	if len(prefix)+len(postfix) > addressHexLength {
		return fmt.Errorf("combined prefix and postfix length must not exceed %d hex characters", addressHexLength)
	}
	return nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
