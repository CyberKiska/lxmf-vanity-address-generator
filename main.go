package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
)

// CLI flags
var (
	prefix  string
	postfix string
	workers int
	outPath string
	dryRun  bool
)

// Parsed prefix/postfix patterns for fast matching
var (
	prefixNibbles  []byte
	postfixNibbles []byte
)

// Global counters
var (
	totalAttempts uint64
	found         uint32
)

// Identity represents a Reticulum identity with Ed25519 and X25519 key pairs
type Identity struct {
	X25519Private [32]byte // X25519 private key (encryption)
	X25519Public  [32]byte // X25519 public key
	Ed25519Seed   [32]byte // Ed25519 seed (signing)
	Ed25519Public [32]byte // Ed25519 public key
	Hash          [16]byte // Identity hash (SHA-256 of public key, truncated)
	Address       [16]byte // LXMF destination address
}

func init() {
	flag.StringVar(&prefix, "prefix", "", "Desired hex prefix (1-32 chars)")
	flag.StringVar(&postfix, "postfix", "", "Desired hex postfix/suffix (1-32 chars)")
	flag.IntVar(&workers, "workers", runtime.NumCPU(), "Number of parallel workers")
	flag.StringVar(&outPath, "out", "identity", "Output path for identity file")
	flag.BoolVar(&dryRun, "dry-run", false, "Only measure speed, don't save")
}

func main() {
	flag.Parse()

	// Validate and normalize inputs
	if err := validateInputs(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	prefix = strings.ToLower(prefix)
	postfix = strings.ToLower(postfix)

	// Parse patterns for fast comparison
	if prefix != "" {
		prefixNibbles = hexToNibbles(prefix)
	}
	if postfix != "" {
		postfixNibbles = hexToNibbles(postfix)
	}

	fmt.Printf("Searching for LXMF vanity address...\n")
	if prefix != "" {
		fmt.Printf("  Prefix:  %s\n", prefix)
	}
	if postfix != "" {
		fmt.Printf("  Postfix: %s\n", postfix)
	}
	fmt.Printf("  Workers: %d\n", workers)
	if dryRun {
		fmt.Printf("  Mode:    DRY RUN (speed test only)\n")
	}
	fmt.Println()

	// Start worker pool and monitoring
	go monitorProgress()

	resultChan := make(chan *Identity, 1)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(&wg, resultChan)
	}

	// Wait for result and stop workers
	identity := <-resultChan
	atomic.StoreUint32(&found, 1)

	wg.Wait()

	// Display result
	addrHex := hex.EncodeToString(identity.Address[:])
	fmt.Printf("\n✓ Found matching address: %s\n", addrHex)
	fmt.Printf("  Total attempts: %d\n", atomic.LoadUint64(&totalAttempts))

	if !dryRun {
		if err := saveIdentity(identity, outPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving identity: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Saved to: %s\n", outPath)
	}
}

func validateInputs() error {
	// Validate prefix
	if prefix != "" {
		if len(prefix) > 32 {
			return fmt.Errorf("prefix must be 1-32 hex characters")
		}
		if !isHex(prefix) {
			return fmt.Errorf("prefix must contain only hex characters [0-9a-fA-F]")
		}
	}

	// Validate postfix
	if postfix != "" {
		if len(postfix) > 32 {
			return fmt.Errorf("postfix must be 1-32 hex characters")
		}
		if !isHex(postfix) {
			return fmt.Errorf("postfix must contain only hex characters [0-9a-fA-F]")
		}
	}

	if prefix == "" && postfix == "" {
		return fmt.Errorf("at least one of --prefix or --postfix must be specified")
	}

	if workers < 1 {
		return fmt.Errorf("workers must be at least 1")
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

func worker(wg *sync.WaitGroup, resultChan chan<- *Identity) {
	defer wg.Done()

	// Pre-allocate buffers for performance
	var randBuf [64]byte

	// Pre-compute name hash for LXMF (constant across all iterations)
	nameHashFull := sha256.Sum256([]byte("lxmf.delivery"))
	nameHash := nameHashFull[:10]

	for {
		// Check if another worker found a match
		if atomic.LoadUint32(&found) == 1 {
			return
		}

		// Generate random bytes
		if _, err := rand.Read(randBuf[:]); err != nil {
			continue
		}

		// Create and derive identity
		var identity Identity
		copy(identity.X25519Private[:], randBuf[0:32])
		copy(identity.Ed25519Seed[:], randBuf[32:64])

		// Generate key pairs
		clampX25519(&identity.X25519Private)
		curve25519.ScalarBaseMult(&identity.X25519Public, &identity.X25519Private)
		generateEd25519Public(&identity)

		// Build public key and compute hashes
		var publicKey [64]byte
		copy(publicKey[0:32], identity.X25519Public[:])
		copy(publicKey[32:64], identity.Ed25519Public[:])

		identityHashFull := sha256.Sum256(publicKey[:])
		copy(identity.Hash[:], identityHashFull[:16])

		// Compute LXMF destination address
		var addrHashMaterial [26]byte
		copy(addrHashMaterial[0:10], nameHash)
		copy(addrHashMaterial[10:26], identity.Hash[:])

		addrHashFull := sha256.Sum256(addrHashMaterial[:])
		copy(identity.Address[:], addrHashFull[:16])

		// Check if address matches pattern
		atomic.AddUint64(&totalAttempts, 1)
		if matchesPattern(identity.Address[:]) {
			select {
			case resultChan <- &identity:
			default:
			}
			return
		}
	}
}

func generateEd25519Public(identity *Identity) {
	// Generate Ed25519 public key from seed (crypto/ed25519 handles SHA-512 internally)
	publicKey := ed25519.NewKeyFromSeed(identity.Ed25519Seed[:]).Public().(ed25519.PublicKey)
	copy(identity.Ed25519Public[:], publicKey)
}

func clampX25519(privateKey *[32]byte) {
	privateKey[0] &= 248  // Clear 3 lowest bits
	privateKey[31] &= 127 // Clear highest bit
	privateKey[31] |= 64  // Set second-highest bit
}

// hexToNibbles converts hex string to nibbles for fast comparison
func hexToNibbles(s string) []byte {
	nibbles := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			nibbles[i] = c - '0'
		} else if c >= 'a' && c <= 'f' {
			nibbles[i] = c - 'a' + 10
		}
	}
	return nibbles
}

// matchesPattern checks if address matches prefix/postfix patterns using nibble comparison
func matchesPattern(addr []byte) bool {
	// Check prefix
	if len(prefixNibbles) > 0 {
		for i := 0; i < len(prefixNibbles); i++ {
			byteIdx := i / 2
			nibble := byte(0)
			if i%2 == 0 {
				nibble = (addr[byteIdx] >> 4) & 0x0F
			} else {
				nibble = addr[byteIdx] & 0x0F
			}
			if nibble != prefixNibbles[i] {
				return false
			}
		}
	}

	// Check postfix
	if len(postfixNibbles) > 0 {
		addrLen := len(addr) * 2
		startNibble := addrLen - len(postfixNibbles)

		for i := 0; i < len(postfixNibbles); i++ {
			nibbleIdx := startNibble + i
			byteIdx := nibbleIdx / 2
			nibble := byte(0)
			if nibbleIdx%2 == 0 {
				nibble = (addr[byteIdx] >> 4) & 0x0F
			} else {
				nibble = addr[byteIdx] & 0x0F
			}
			if nibble != postfixNibbles[i] {
				return false
			}
		}
	}

	return true
}

func monitorProgress() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	lastAttempts := uint64(0)
	startTime := time.Now()
	
	for {
		<-ticker.C
		
		if atomic.LoadUint32(&found) == 1 {
			return
		}
		
		current := atomic.LoadUint64(&totalAttempts)
		rate := current - lastAttempts
		lastAttempts = current
		
		elapsed := time.Since(startTime).Seconds()
		avgRate := float64(current) / elapsed
		
		fmt.Printf("\r  Speed: %s/s (avg: %s/s) | Total: %s        ",
			formatNumber(rate),
			formatNumber(uint64(avgRate)),
			formatNumber(current))
	}
}

func formatNumber(n uint64) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.2fM", float64(n)/1000000)
	} else if n >= 1000 {
		return fmt.Sprintf("%.2fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func saveIdentity(identity *Identity, path string) error {
	// Save binary identity file (X25519 private + Ed25519 seed)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(identity.X25519Private[:]); err != nil {
		return err
	}
	if _, err := file.Write(identity.Ed25519Seed[:]); err != nil {
		return err
	}

	// Create human-readable info file
	infoPath := path + ".txt"
	infoFile, err := os.Create(infoPath)
	if err != nil {
		return err
	}
	defer infoFile.Close()

	fmt.Fprintf(infoFile, "LXMF Vanity Address Identity\n")
	fmt.Fprintf(infoFile, "============================\n\n")
	fmt.Fprintf(infoFile, "Address (LXMF): %s\n", hex.EncodeToString(identity.Address[:]))
	fmt.Fprintf(infoFile, "Identity Hash:  %s\n\n", hex.EncodeToString(identity.Hash[:]))

	fmt.Fprintf(infoFile, "Public Key (X25519 + Ed25519):\n")
	fmt.Fprintf(infoFile, "  X25519 Public:  %s\n", hex.EncodeToString(identity.X25519Public[:]))
	fmt.Fprintf(infoFile, "  Ed25519 Public: %s\n\n", hex.EncodeToString(identity.Ed25519Public[:]))

	// Prepare combined identity bytes (X25519 private + Ed25519 seed)
	var privKey [64]byte
	copy(privKey[0:32], identity.X25519Private[:])
	copy(privKey[32:64], identity.Ed25519Seed[:])

	// Encoders: standard Base64 (padded) and Base32 (padded, uppercase)
	b64 := base64.StdEncoding.EncodeToString(privKey[:])
	b32 := base32.StdEncoding.EncodeToString(privKey[:])

	fmt.Fprintf(infoFile, "Private Key (X25519 + Ed25519):\n")
	fmt.Fprintf(infoFile, "  X25519 Private: %s\n", hex.EncodeToString(identity.X25519Private[:]))
	fmt.Fprintf(infoFile, "  Ed25519 Seed:   %s\n", hex.EncodeToString(identity.Ed25519Seed[:]))
	fmt.Fprintln(infoFile)

	// MeshChat/Sideband import formats of the identity bytes
	fmt.Fprintf(infoFile, "--- Import formats ---\n")
	fmt.Fprintf(infoFile, "Base64 (MeshChat import string):\n%s\n", b64)
	fmt.Fprintf(infoFile, "Base32 (Sideband import string):\n%s\n", b32)

	return nil
}
