package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	addressHexLength        = 32
	addressByteLength       = addressHexLength / 2
	identityPrivateKeySize  = 64
	attemptFlushInterval    = 1024
	maxWorkerCount          = 256
	base64PrivateExportSize = 88
	base32PrivateExportSize = 104
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

var lxmfNameHash = func() [10]byte {
	full := sha256.Sum256([]byte("lxmf.delivery"))
	var out [10]byte
	copy(out[:], full[:10])
	return out
}()

// Identity contains the Reticulum X25519 encryption and Ed25519 signing keys
// needed to persist a private identity and derive its LXMF delivery address.
type Identity struct {
	X25519Private [32]byte
	X25519Public  [32]byte
	Ed25519Seed   [32]byte
	Ed25519Public [32]byte
	Hash          [16]byte
	Address       [16]byte
}

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

type searcher struct {
	matcher     addressMatcher
	rng         io.Reader
	stopOnMatch bool
	attempts    atomic.Uint64
}

type searchOutcome struct {
	identity Identity
	err      error
}

func newSearcher(matcher addressMatcher, rng io.Reader) *searcher {
	return &searcher{matcher: matcher, rng: rng, stopOnMatch: true}
}

func (s *searcher) run(parent context.Context, workerCount int) (Identity, error) {
	if workerCount < 1 || workerCount > maxWorkerCount {
		return Identity{}, fmt.Errorf("invalid worker count %d", workerCount)
	}
	if s.rng == nil {
		return Identity{}, fmt.Errorf("secure random source is nil")
	}
	s.attempts.Store(0)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	outcomes := make(chan searchOutcome, 1)
	var publishOnce sync.Once
	publish := func(outcome searchOutcome) {
		defer wipeIdentitySecrets(&outcome.identity)
		publishOnce.Do(func() {
			outcomes <- outcome
			cancel()
		})
	}

	var workersDone sync.WaitGroup
	workersDone.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go s.worker(ctx, &workersDone, publish)
	}

	var outcome searchOutcome
	defer wipeIdentitySecrets(&outcome.identity)
	select {
	case outcome = <-outcomes:
	case <-parent.Done():
		cancel()
		workersDone.Wait()
		// An in-flight candidate can finish during cancellation. Preserve its
		// published result instead of discarding a completed private identity.
		select {
		case outcome = <-outcomes:
		default:
			return Identity{}, parent.Err()
		}
	}

	cancel()
	workersDone.Wait()
	if outcome.err != nil {
		return Identity{}, outcome.err
	}
	return outcome.identity, nil
}

func (s *searcher) worker(ctx context.Context, workersDone *sync.WaitGroup, publish func(searchOutcome)) {
	defer workersDone.Done()

	var localAttempts uint64
	defer flushAttempts(&localAttempts, &s.attempts)

	var randBuf [identityPrivateKeySize]byte
	var identity Identity
	var publicKey [64]byte
	addrHashMaterial := newAddressHashMaterial()
	defer wipeBytes(randBuf[:])
	defer wipeIdentitySecrets(&identity)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if _, err := io.ReadFull(s.rng, randBuf[:]); err != nil {
			publish(searchOutcome{err: fmt.Errorf("secure random source failed: %w", err)})
			return
		}

		if err := deriveCandidate(&identity, &randBuf, &publicKey, &addrHashMaterial); err != nil {
			publish(searchOutcome{err: err})
			return
		}

		localAttempts++
		if localAttempts >= attemptFlushInterval {
			flushAttempts(&localAttempts, &s.attempts)
		}

		if s.stopOnMatch && s.matcher.matches(identity.Address[:]) {
			publish(searchOutcome{identity: identity})
			return
		}
	}
}

func flushAttempts(localAttempts *uint64, totalAttempts *atomic.Uint64) {
	if *localAttempts == 0 {
		return
	}
	totalAttempts.Add(*localAttempts)
	*localAttempts = 0
}

func newAddressHashMaterial() [26]byte {
	var material [26]byte
	copy(material[:10], lxmfNameHash[:])
	return material
}

func deriveCandidate(identity *Identity, randBuf *[identityPrivateKeySize]byte, publicKey *[64]byte, addrHashMaterial *[26]byte) error {
	copy(identity.X25519Private[:], randBuf[0:32])
	copy(identity.Ed25519Seed[:], randBuf[32:64])

	clampX25519(&identity.X25519Private)
	if err := generateX25519Public(identity); err != nil {
		return fmt.Errorf("X25519 public-key derivation unavailable: %w", err)
	}
	generateEd25519Public(identity)

	copy(publicKey[0:32], identity.X25519Public[:])
	copy(publicKey[32:64], identity.Ed25519Public[:])

	identityHashFull := sha256.Sum256(publicKey[:])
	copy(identity.Hash[:], identityHashFull[:16])
	copy(addrHashMaterial[10:26], identityHashFull[:16])

	addrHashFull := sha256.Sum256(addrHashMaterial[:])
	copy(identity.Address[:], addrHashFull[:16])
	return nil
}

func generateX25519Public(identity *Identity) error {
	privateKey, err := ecdh.X25519().NewPrivateKey(identity.X25519Private[:])
	if err != nil {
		return err
	}
	copy(identity.X25519Public[:], privateKey.PublicKey().Bytes())
	runtime.KeepAlive(privateKey)
	return nil
}

func generateEd25519Public(identity *Identity) {
	privateKey := ed25519.NewKeyFromSeed(identity.Ed25519Seed[:])
	copy(identity.Ed25519Public[:], privateKey[32:])
	wipeBytes(privateKey)
}

func clampX25519(privateKey *[32]byte) {
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
}

func wipeIdentitySecrets(identity *Identity) {
	wipeBytes(identity.X25519Private[:])
	wipeBytes(identity.Ed25519Seed[:])
	runtime.KeepAlive(identity)
}

func wipeBytes(data []byte) {
	clear(data)
	runtime.KeepAlive(data)
}

type addressMatcher struct {
	prefixBytes   [addressByteLength]byte
	prefixLen     int
	prefixOdd     byte
	hasPrefixOdd  bool
	postfixBytes  [addressByteLength]byte
	postfixLen    int
	postfixOdd    byte
	hasPostfixOdd bool
}

func newAddressMatcher(prefix, postfix string) (addressMatcher, error) {
	var m addressMatcher
	if err := validatePatterns(prefix, postfix); err != nil {
		return m, err
	}

	prefixEvenChars := len(prefix) &^ 1
	if prefixEvenChars > 0 {
		n, err := hex.Decode(m.prefixBytes[:], []byte(prefix[:prefixEvenChars]))
		if err != nil {
			return m, fmt.Errorf("invalid prefix: %w", err)
		}
		m.prefixLen = n
	}
	if len(prefix)%2 == 1 {
		nibble, ok := hexNibble(prefix[prefixEvenChars])
		if !ok {
			return m, fmt.Errorf("invalid prefix")
		}
		m.prefixOdd = nibble
		m.hasPrefixOdd = true
	}

	postfixStart := 0
	if len(postfix)%2 == 1 {
		nibble, ok := hexNibble(postfix[0])
		if !ok {
			return m, fmt.Errorf("invalid postfix")
		}
		m.postfixOdd = nibble
		m.hasPostfixOdd = true
		postfixStart = 1
	}
	if postfixStart < len(postfix) {
		n, err := hex.Decode(m.postfixBytes[:], []byte(postfix[postfixStart:]))
		if err != nil {
			return m, fmt.Errorf("invalid postfix: %w", err)
		}
		m.postfixLen = n
	}

	return m, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func (m addressMatcher) matches(addr []byte) bool {
	if len(addr) != addressByteLength {
		return false
	}

	for i := 0; i < m.prefixLen; i++ {
		if addr[i] != m.prefixBytes[i] {
			return false
		}
	}
	if m.hasPrefixOdd && addr[m.prefixLen]>>4 != m.prefixOdd {
		return false
	}

	if m.postfixLen > 0 {
		start := addressByteLength - m.postfixLen
		for i := 0; i < m.postfixLen; i++ {
			if addr[start+i] != m.postfixBytes[i] {
				return false
			}
		}
	}
	if m.hasPostfixOdd {
		idx := addressByteLength - m.postfixLen - 1
		if addr[idx]&0x0F != m.postfixOdd {
			return false
		}
	}

	return true
}

func monitorProgress(ctx context.Context, attempts *atomic.Uint64) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastAttempts := uint64(0)
	startTime := time.Now()
	lastTime := startTime
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			current := attempts.Load()
			rate := attemptsPerSecond(current-lastAttempts, now.Sub(lastTime))
			lastAttempts = current
			lastTime = now
			avgRate := attemptsPerSecond(current, now.Sub(startTime))
			fmt.Printf("\r  Speed: %s/s (avg: %s/s) | Total: %s        ",
				formatNumber(rate),
				formatNumber(avgRate),
				formatNumber(current))
		}
	}
}

func attemptsPerSecond(attempts uint64, elapsed time.Duration) uint64 {
	if elapsed <= 0 {
		return 0
	}
	return uint64(float64(attempts) / elapsed.Seconds())
}

func formatNumber(n uint64) string {
	if n >= 1_000_000 {
		return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
	}
	if n >= 1_000 {
		return fmt.Sprintf("%.2fK", float64(n)/1_000)
	}
	return fmt.Sprintf("%d", n)
}

func expectedAttempts(patternHexCharacters int) string {
	if patternHexCharacters < 0 || patternHexCharacters > addressHexLength {
		return "invalid"
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(4*patternHexCharacters)).String()
}

func (o *outputTarget) saveIdentity(identity *Identity, privateExports bool) error {
	path := o.path
	if err := validateIdentityConsistency(identity); err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("output path must not be empty")
	}
	// The preflight checks target availability before searching. At save time,
	// let the no-replace writer preserve a complete recovery file on collision.
	// A metadata collision must not prevent saving the primary identity.

	var privateKey [identityPrivateKeySize]byte
	defer wipeBytes(privateKey[:])
	copy(privateKey[0:32], identity.X25519Private[:])
	copy(privateKey[32:64], identity.Ed25519Seed[:])

	if err := o.writeFile(o.name, privateKey[:], 0o600, o.root.Link, true); err != nil {
		return fmt.Errorf("save identity: %w", errors.Join(err, o.checkLocation()))
	}
	if err := o.writeIdentityInfo(identity, privateExports); err != nil {
		return fmt.Errorf("identity was saved to %s, but metadata could not be saved: %w", path, errors.Join(err, o.checkLocation()))
	}
	return o.checkLocation()
}

func validateIdentityConsistency(identity *Identity) error {
	if identity == nil {
		return fmt.Errorf("identity must not be nil")
	}

	var input [identityPrivateKeySize]byte
	var expected Identity
	var publicKey [64]byte
	material := newAddressHashMaterial()
	defer wipeBytes(input[:])
	defer wipeIdentitySecrets(&expected)
	copy(input[0:32], identity.X25519Private[:])
	copy(input[32:64], identity.Ed25519Seed[:])
	if err := deriveCandidate(&expected, &input, &publicKey, &material); err != nil {
		return err
	}

	valid := 1
	valid &= subtle.ConstantTimeCompare(identity.X25519Private[:], expected.X25519Private[:])
	valid &= subtle.ConstantTimeCompare(identity.Ed25519Seed[:], expected.Ed25519Seed[:])
	valid &= subtle.ConstantTimeCompare(identity.X25519Public[:], expected.X25519Public[:])
	valid &= subtle.ConstantTimeCompare(identity.Ed25519Public[:], expected.Ed25519Public[:])
	valid &= subtle.ConstantTimeCompare(identity.Hash[:], expected.Hash[:])
	valid &= subtle.ConstantTimeCompare(identity.Address[:], expected.Address[:])
	if valid != 1 {
		return fmt.Errorf("identity fields are inconsistent with the private key material; refusing to save")
	}
	return nil
}

func (o *outputTarget) writeIdentityInfo(identity *Identity, privateExports bool) error {
	var publicKey [64]byte
	copy(publicKey[0:32], identity.X25519Public[:])
	copy(publicKey[32:64], identity.Ed25519Public[:])

	var info bytes.Buffer
	info.Grow(768)
	fmt.Fprintln(&info, "LXMF Vanity Address Identity")
	fmt.Fprintln(&info, "============================")
	fmt.Fprintln(&info)
	fmt.Fprintf(&info, "Address (LXMF): %s\n", hex.EncodeToString(identity.Address[:]))
	fmt.Fprintf(&info, "Identity Hash:  %s\n", hex.EncodeToString(identity.Hash[:]))
	fmt.Fprintf(&info, "Full Specifier: <lxmf.delivery.%s:%s>\n\n",
		hex.EncodeToString(identity.Hash[:]),
		hex.EncodeToString(identity.Address[:]),
	)
	fmt.Fprintln(&info, "Public Key (X25519 + Ed25519):")
	fmt.Fprintf(&info, "  X25519 Public:  %s\n", hex.EncodeToString(identity.X25519Public[:]))
	fmt.Fprintf(&info, "  Ed25519 Public: %s\n", hex.EncodeToString(identity.Ed25519Public[:]))
	fmt.Fprintf(&info, "  Combined:       %s\n\n", hex.EncodeToString(publicKey[:]))
	fmt.Fprintf(&info, "Private identity file: %q\n", o.path)
	if !privateExports {
		fmt.Fprintln(&info, "This metadata file contains public information only.")
	}

	if privateExports {
		// Reserve enough additional capacity before private encodings enter the
		// buffer, so a later growth cannot leave an abandoned secret-bearing copy.
		info.Grow(512)
		var privateKey [identityPrivateKeySize]byte
		var encodedBase64 [base64PrivateExportSize]byte
		var encodedBase32 [base32PrivateExportSize]byte
		defer wipeBytes(privateKey[:])
		defer wipeBytes(encodedBase64[:])
		defer wipeBytes(encodedBase32[:])

		copy(privateKey[0:32], identity.X25519Private[:])
		copy(privateKey[32:64], identity.Ed25519Seed[:])
		base64.URLEncoding.Encode(encodedBase64[:], privateKey[:])
		base32.StdEncoding.Encode(encodedBase32[:], privateKey[:])

		fmt.Fprintln(&info)
		fmt.Fprintln(&info, "WARNING: Reversible private identity exports follow. Protect this file like the identity file.")
		fmt.Fprintln(&info, "Reticulum URL-safe Base64 private identity:")
		info.WriteString("  ")
		info.Write(encodedBase64[:])
		info.WriteByte('\n')
		fmt.Fprintln(&info, "Reticulum Base32 private identity:")
		info.WriteString("  ")
		info.Write(encodedBase32[:])
		info.WriteByte('\n')
	}

	fmt.Fprintln(&info)
	fmt.Fprintln(&info, "Verify with:")
	fmt.Fprintln(&info, "  rnid -i <identity_file> -H lxmf.delivery")

	if privateExports {
		defer wipeBytes(info.Bytes())
	}
	return o.writeFile(o.name+".txt", info.Bytes(), 0o600, o.root.Link, false)
}

// outputTarget holds the directory open from preflight through publication. All
// filesystem mutations use relative names within this root, including cleanup.
// The directory must still be trusted: a root does not remove another user's
// permission to alter its entries.
type outputTarget struct {
	root *os.Root
	path string
	name string
}

func openOutputTarget(path string) (*outputTarget, error) {
	if path == "" || strings.HasSuffix(path, string(os.PathSeparator)) {
		return nil, fmt.Errorf("output path must name a file")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(absolute)
	if name == "." || !filepath.IsLocal(name) {
		return nil, fmt.Errorf("invalid output filename %q", name)
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, fmt.Errorf("open output directory: %w", err)
	}
	return &outputTarget{root: root, path: absolute, name: name}, nil
}

func (o *outputTarget) preflight() error {
	for _, name := range []string{o.name, o.name + ".txt"} {
		if err := o.ensureDoesNotExist(name); err != nil {
			return err
		}
	}
	// Exercise the longest temporary filename too, before spending time mining.
	probe, name, err := o.createTemp(o.name + ".txt")
	if err != nil {
		return fmt.Errorf("output directory is not writable: %w", err)
	}
	chmodErr := probe.Chmod(0o600)
	closeErr := probe.Close()
	removeErr := o.root.Remove(name)
	if err := errors.Join(chmodErr, closeErr, removeErr); err != nil {
		return err
	}
	return o.checkLocation()
}

func (o *outputTarget) createTemp(base string) (*os.File, string, error) {
	for range 10 {
		name := base + ".tmp-" + rand.Text()
		file, err := o.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return file, name, err
	}
	return nil, "", fmt.Errorf("could not allocate an exclusive temporary file")
}

func (o *outputTarget) ensureDoesNotExist(name string) error {
	if _, err := o.root.Lstat(name); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite", filepath.Join(o.root.Name(), name))
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (o *outputTarget) checkLocation() error {
	original, originalErr := o.root.Stat(".")
	current, currentErr := os.Stat(o.root.Name())
	if originalErr != nil || currentErr != nil || !os.SameFile(original, current) {
		return fmt.Errorf("output directory %q moved or was replaced; output and recovery filenames refer to the originally opened directory, not its replacement", o.root.Name())
	}
	return nil
}

type recoverableWriteError struct {
	target       string
	recoveryPath string
	cause        error
}

func (e *recoverableWriteError) Error() string {
	return fmt.Sprintf("could not publish %s; the complete temporary data was retained at %s for recovery: %v", e.target, e.recoveryPath, e.cause)
}

func (e *recoverableWriteError) Unwrap() error {
	return e.cause
}

// writeFile prefers atomic no-replace hard-link publication. The exclusive
// fallback preserves no-overwrite semantics but is not crash-atomic.
func (o *outputTarget) writeFile(path string, data []byte, mode os.FileMode, link func(string, string) error, preserveCompleteTemp bool) error {
	file, tempPath, err := o.createTemp(path)
	if err != nil {
		return err
	}
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = o.root.Remove(tempPath)
		}
	}()

	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	linkErr := link(tempPath, path)
	if linkErr == nil {
		if err := o.root.Remove(tempPath); err != nil {
			removeTemp = false
			o.syncDirBestEffort()
			return fmt.Errorf("published %s, but could not remove the temporary hard link %s: %w", path, tempPath, err)
		}
		removeTemp = false
		o.syncDirBestEffort()
		return nil
	}
	if err := o.ensureDoesNotExist(path); err != nil {
		if preserveCompleteTemp {
			removeTemp = false
			o.syncDirBestEffort()
			return &recoverableWriteError{target: path, recoveryPath: filepath.Join(o.root.Name(), tempPath), cause: errors.Join(linkErr, err)}
		}
		return err
	}

	if err := o.writeFileExclusive(path, data, mode); err != nil {
		if preserveCompleteTemp {
			removeTemp = false
			o.syncDirBestEffort()
			return &recoverableWriteError{target: path, recoveryPath: filepath.Join(o.root.Name(), tempPath), cause: errors.Join(linkErr, err)}
		}
		return fmt.Errorf("atomic publication unavailable (%v); exclusive fallback failed: %w", linkErr, err)
	}
	if err := o.root.Remove(tempPath); err != nil {
		removeTemp = false
		o.syncDirBestEffort()
		return fmt.Errorf("published %s through the exclusive fallback, but could not remove complete temporary file %s: %w", path, tempPath, err)
	}
	removeTemp = false
	o.syncDirBestEffort()
	return nil
}

func (o *outputTarget) writeFileExclusive(path string, data []byte, mode os.FileMode) (err error) {
	file, err := o.root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; refusing to overwrite", path)
		}
		return err
	}

	complete := false
	defer func() {
		if !complete {
			file.Close()
			o.root.Remove(path)
		}
	}()

	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	complete = true
	return nil
}

func (o *outputTarget) syncDirBestEffort() {
	file, err := o.root.Open(".")
	if err != nil {
		return
	}
	defer file.Close()
	_ = file.Sync()
}
