package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"
)

type config struct {
	prefix                string
	postfix               string
	workers               int
	outPath               string
	fallbackOut           string
	saveRetryTimeout      time.Duration
	maxAttempts           uint64
	timeout               time.Duration
	generator             string
	inspectPath           string
	explicit              map[string]bool
	dryRun                bool
	includePrivateExports bool
	benchmarkDuration     time.Duration
	allowInheritedWinACL  bool
}

func parseArgs(args []string, usage io.Writer) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("lxmf-vanity", flag.ContinueOnError)
	flags.SetOutput(usage)
	flags.StringVar(&cfg.prefix, "prefix", "", "Desired hex prefix (1-32 chars)")
	flags.StringVar(&cfg.postfix, "postfix", "", "Desired hex postfix/suffix (1-32 chars)")
	flags.IntVar(&cfg.workers, "workers", defaultWorkerCount(), "Number of parallel workers")
	flags.StringVar(&cfg.outPath, "out", "identity", "Output path for identity file")
	flags.BoolVar(&cfg.dryRun, "dry-run", false, "Find a match but do not save it")
	flags.BoolVar(&cfg.includePrivateExports, "include-private-exports", false, "Include reversible private-key exports in <out>.txt (sensitive)")
	flags.DurationVar(&cfg.benchmarkDuration, "benchmark", 0, "Benchmark full identity generation for a duration (for example 30s); no identity is selected or saved")
	flags.BoolVar(&cfg.allowInheritedWinACL, "allow-inherited-windows-acl", false, "On Windows, explicitly accept the output directory's inherited ACL for private files")
	flags.StringVar(&cfg.fallbackOut, "fallback-out", "", "Preflighted secondary identity file for save recovery")
	flags.DurationVar(&cfg.saveRetryTimeout, "save-retry-timeout", 0, "Save recovery deadline; 0 retries indefinitely (cannot interrupt blocked I/O)")
	flags.Uint64Var(&cfg.maxAttempts, "max-attempts", 0, "Maximum reserved candidates; 0 is unlimited")
	flags.DurationVar(&cfg.timeout, "timeout", 0, "Search timeout; 0 is unlimited (does not limit saving)")
	flags.StringVar(&cfg.generator, "generator", "segmented", "Candidate generator: segmented or independent")
	flags.StringVar(&cfg.inspectPath, "inspect", "", "Print public metadata for a 64-byte identity; write nothing")
	if err := flags.Parse(args); err != nil {
		return cfg, err
	}
	if flags.NArg() != 0 {
		return cfg, fmt.Errorf("unexpected positional arguments %q; all options must use flags", flags.Args())
	}
	cfg.explicit = make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { cfg.explicit[f.Name] = true })
	cfg.prefix = strings.ToLower(cfg.prefix)
	cfg.postfix = strings.ToLower(cfg.postfix)
	return cfg, validateInputs(cfg)
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

func validateInputs(cfg config) error {
	if cfg.inspectPath != "" {
		for name := range cfg.explicit {
			if name != "inspect" && name != "json" {
				return fmt.Errorf("--inspect cannot be combined with --%s", name)
			}
		}
		return nil
	}
	if cfg.generator != "" && cfg.generator != "segmented" && cfg.generator != "independent" {
		return fmt.Errorf("generator must be segmented or independent")
	}
	if cfg.timeout < 0 {
		return fmt.Errorf("timeout must not be negative")
	}
	if cfg.benchmarkDuration > 0 && (cfg.timeout > 0 || cfg.maxAttempts > 0) {
		return fmt.Errorf("benchmark cannot be combined with search limits")
	}
	if cfg.saveRetryTimeout < 0 {
		return fmt.Errorf("save retry timeout must not be negative")
	}
	if (cfg.dryRun || cfg.benchmarkDuration > 0) && (cfg.fallbackOut != "" || cfg.saveRetryTimeout != 0) {
		return fmt.Errorf("save recovery options require saving mode")
	}
	if cfg.benchmarkDuration < 0 {
		return fmt.Errorf("benchmark duration must not be negative")
	}
	if cfg.benchmarkDuration > 0 {
		if cfg.prefix != "" || cfg.postfix != "" {
			return fmt.Errorf("--benchmark cannot be combined with --prefix or --postfix")
		}
		if cfg.dryRun {
			return fmt.Errorf("--benchmark cannot be combined with --dry-run")
		}
		if cfg.includePrivateExports {
			return fmt.Errorf("--benchmark cannot be combined with --include-private-exports")
		}
	} else {
		if err := validatePatterns(cfg.prefix, cfg.postfix); err != nil {
			return err
		}
	}
	if cfg.workers < 1 {
		return fmt.Errorf("workers must be at least 1")
	}
	if cfg.workers > maxWorkerCount {
		return fmt.Errorf("workers must not exceed %d", maxWorkerCount)
	}
	if cfg.dryRun && cfg.includePrivateExports {
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

func targetsOverlap(a, b *outputTarget) bool {
	ai, e1 := a.root.Stat(".")
	bi, e2 := b.root.Stat(".")
	if e1 != nil || e2 != nil || !os.SameFile(ai, bi) {
		return false
	}
	for _, left := range []string{a.name, a.name + ".txt"} {
		for _, right := range []string{b.name, b.name + ".txt"} {
			if left == right || (runtime.GOOS == "windows" || runtime.GOOS == "darwin") && strings.EqualFold(left, right) {
				return true
			}
		}
	}
	return false
}
