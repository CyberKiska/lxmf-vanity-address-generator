package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

	if err := o.writeFile(o.name, privateKey[:], 0o600, true); err != nil {
		return fmt.Errorf("save identity: %w", errors.Join(err, o.checkLocation()))
	}
	if err := o.writeIdentityInfo(identity, privateExports); err != nil {
		return fmt.Errorf("identity was saved to %s, but metadata could not be saved: %w", path, errors.Join(err, o.checkLocation()))
	}
	return o.checkLocation()
}

type outputTarget struct {
	root dirOps
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
	return &outputTarget{root: rootDir{root}, path: absolute, name: name}, nil
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

func (o *outputTarget) createTemp(base string) (fileOps, string, error) {
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
func (o *outputTarget) writeFile(path string, data []byte, mode os.FileMode, preserveCompleteTemp bool) error {
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

	linkErr := o.root.Link(tempPath, path)
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
	file, err := o.root.OpenFile(".", os.O_RDONLY, 0)
	if err != nil {
		return
	}
	defer file.Close()
	_ = file.Sync()
}
