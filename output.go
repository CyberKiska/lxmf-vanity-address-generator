package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// All mutations and reads remain anchored to the originally opened directory.
type outputTarget struct {
	root       dirOps
	path, name string
	exclusive  bool
	allowWeak  bool
	notices    []string
	retained   []*ownedFile
	deviations []string
}

type ownedFile struct {
	name     string
	info     os.FileInfo
	complete bool
}

// Paths contain no secret bytes. Written files are not called saved until a
// protected descriptor read-back and file sync have succeeded.
type saveResult struct {
	Verified        []string
	Unverified      []string
	Deviations      []string
	LocationChanged bool
	internal        bool
	cause           error
}

func (r saveResult) saved() bool { return len(r.Verified) > 0 }
func (o *outputTarget) note(err error) {
	if err != nil {
		o.deviations = appendUnique(o.deviations, err.Error())
	}
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}
func openOutputTarget(path string) (*outputTarget, error) {
	if path == "" || os.IsPathSeparator(path[len(path)-1]) {
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
func (o *outputTarget) createTemp(base string) (fileOps, string, error) {
	for range 10 {
		name := base + ".tmp-" + rand.Text()
		f, err := o.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return f, name, err
	}
	return nil, "", fmt.Errorf("could not allocate an exclusive temporary file")
}
func (o *outputTarget) ensureDoesNotExist(name string) error {
	if _, err := o.root.Lstat(name); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite", o.fullPath(name))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (o *outputTarget) fullPath(name string) string { return filepath.Join(o.root.Name(), name) }
func (o *outputTarget) checkLocation() error {
	original, e1 := o.root.Stat(".")
	current, e2 := os.Stat(o.root.Name())
	if e1 != nil || e2 != nil || !os.SameFile(original, current) {
		return fmt.Errorf("output directory %q moved or was replaced; files are inside the originally opened directory, which is no longer at the requested path", o.root.Name())
	}
	return nil
}
func linkUnsupported(err error) bool {
	return errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EXDEV)
}
func (o *outputTarget) removeOwned(f *ownedFile) error {
	current, err := o.root.Lstat(f.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check cleanup %s: %w", o.fullPath(f.name), err)
	}
	if f.info == nil || !os.SameFile(f.info, current) {
		return fmt.Errorf("refusing cleanup of replaced or unverified entry %s", o.fullPath(f.name))
	}
	if err := o.root.Remove(f.name); err != nil {
		return fmt.Errorf("remove %s: %w", o.fullPath(f.name), err)
	}
	return nil
}
func (o *outputTarget) writeOpened(f fileOps, name string, data []byte) (*ownedFile, error) {
	record := &ownedFile{name: name}
	info, statErr := f.Stat()
	record.info = info
	chmodErr := f.Chmod(0600)
	// Protection is rechecked on the descriptor before any secret byte is written.
	protected, protectionErr := f.Stat()
	if protectionErr == nil && !protected.Mode().IsRegular() {
		protectionErr = fmt.Errorf("output is not a regular file")
	}
	if protectionErr == nil {
		protectionErr = o.protection(fileProtection(protected))
	}
	if err := errors.Join(statErr, chmodErr, protectionErr); err != nil {
		return record, errors.Join(err, f.Close())
	}
	n, writeErr := f.Write(data)
	record.complete = n == len(data)
	if !record.complete && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	var syncErr error
	if record.complete {
		syncErr = f.Sync()
	}
	closeErr := f.Close()
	return record, errors.Join(writeErr, syncErr, closeErr)
}
func (o *outputTarget) verifyOwned(record *ownedFile, data []byte, syncFile bool) (err error) {
	entry, err := o.root.Lstat(record.name)
	if err != nil {
		return err
	}
	if !entry.Mode().IsRegular() || record.info == nil || !os.SameFile(entry, record.info) {
		return fmt.Errorf("verification: %s was replaced or is not regular", o.fullPath(record.name))
	}
	flags := safeReadFlags
	if syncFile {
		flags |= os.O_RDWR
	}
	f, err := o.root.OpenFile(record.name, flags, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, record.info) || info.Size() != int64(len(data)) {
		return fmt.Errorf("verification: unexpected file identity/type/size at %s", o.fullPath(record.name))
	}
	if err := o.protection(fileProtection(info)); err != nil {
		return fmt.Errorf("verification: %w", err)
	}
	buf := make([]byte, len(data)+1)
	defer wipeBytes(buf)
	n, readErr := io.ReadFull(f, buf)
	if n != len(data) || (readErr != io.EOF && readErr != io.ErrUnexpectedEOF) || !bytes.Equal(buf[:n], data) {
		return fmt.Errorf("verification: read-back differs at %s: %w", o.fullPath(record.name), errors.Join(readErr, io.ErrUnexpectedEOF))
	}
	if syncFile {
		if err := f.Sync(); err != nil {
			return fmt.Errorf("sync %s: %w", o.fullPath(record.name), err)
		}
	}
	return nil
}
func (o *outputTarget) syncDirectory() error {
	f, err := o.root.OpenFile(".", os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("directory durability unavailable: %w", err)
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if errors.Is(syncErr, syscall.EINVAL) || errors.Is(syncErr, syscall.ENOTSUP) {
		return fmt.Errorf("directory sync unsupported on this filesystem; power-loss durability is not verified")
	}
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("directory sync/close: %w", err)
	}
	return nil
}

func (o *outputTarget) protection(err error) error {
	if err == nil {
		return nil
	}
	if !o.allowWeak {
		return fmt.Errorf("output protection refused: %w; use --allow-weak-output-protection only for an intentionally trusted location", err)
	}
	o.notices = appendUnique(o.notices, "Weak output protection explicitly accepted: "+err.Error())
	return nil
}
func (o *outputTarget) preflight() (err error) {
	directory, err := o.root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect opened output directory: %w", err)
	}
	notice, policyErr := directoryProtection(directory)
	if err := o.protection(policyErr); err != nil {
		return err
	}
	if notice != "" {
		o.notices = appendUnique(o.notices, notice)
	}
	// Advisory Git notice uses only directory entries, never Git commands/hooks.
	if _, err := o.root.Lstat(".git"); err == nil {
		o.notices = appendUnique(o.notices, "Output directory is a Git checkout; prefer a private directory outside source control.")
	}

	for _, name := range []string{o.name, o.name + ".txt"} {
		if err := o.ensureDoesNotExist(name); err != nil {
			return err
		}
	}
	var probes []*ownedFile
	defer func() {
		for _, p := range probes {
			err = errors.Join(err, o.removeOwned(p))
		}
	}()
	f, name, err := o.createTemp(o.name + ".txt")
	if err != nil {
		return fmt.Errorf("preflight create probe: %w", err)
	}
	zeros := make([]byte, identityPrivateKeySize)
	a, err := o.writeOpened(f, name, zeros)
	probes = append(probes, a)
	if err != nil {
		return fmt.Errorf("preflight write/sync/close: %w", err)
	}
	var b *ownedFile
	for range 10 {
		probeName := o.name + ".txt.tmp-" + rand.Text()
		linkErr := o.root.Link(a.name, probeName)
		if errors.Is(linkErr, os.ErrExist) {
			continue
		}
		if linkErr == nil {
			b = &ownedFile{name: probeName, info: a.info, complete: true}
			probes = append(probes, b)
			break
		}
		if !linkUnsupported(linkErr) {
			return fmt.Errorf("preflight link: %w", linkErr)
		}
		o.exclusive = true
		file, err := o.root.OpenFile(probeName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("preflight fallback create: %w", err)
		}
		b, err = o.writeOpened(file, probeName, zeros)
		probes = append(probes, b)
		if err != nil {
			return fmt.Errorf("preflight fallback write/sync/close: %w", err)
		}
		break
	}
	if b == nil {
		return fmt.Errorf("preflight probe publication exhausted")
	}
	if err := o.verifyOwned(b, zeros, false); err != nil {
		return fmt.Errorf("preflight read-back: %w", err)
	}
	return o.checkLocation()
}

// persist keeps at most two owned files. Complete files are reused on retries;
// a replacement is verified before a corrupt predecessor can be retired.
func (o *outputTarget) persist(name string, data []byte, state *[]*ownedFile) (saved string, err error) {
	var candidate *ownedFile
	var remaining []*ownedFile
	for _, f := range *state {
		if !f.complete {
			if cleanupErr := o.removeOwned(f); cleanupErr != nil {
				o.note(cleanupErr)
				remaining = append(remaining, f)
			}
			continue
		}
		remaining = append(remaining, f)
		if verifyErr := o.verifyOwned(f, data, true); verifyErr == nil && candidate == nil {
			candidate = f
		} else if verifyErr != nil {
			o.note(verifyErr)
		}
	}
	*state = remaining
	if candidate == nil {
		if len(*state) >= 2 {
			return "", fmt.Errorf("retained file limit reached; cannot create another recovery file")
		}
		file, temp, createErr := o.createTemp(name)
		if createErr != nil {
			return "", fmt.Errorf("create recovery temporary: %w", createErr)
		}
		record, writeErr := o.writeOpened(file, temp, data)
		*state = append(*state, record)
		if writeErr != nil {
			if !record.complete {
				if cleanupErr := o.removeOwned(record); cleanupErr == nil {
					*state = (*state)[:len(*state)-1]
				} else {
					o.note(cleanupErr)
				}
			}
			return "", fmt.Errorf("write/sync/close %s: %w", o.fullPath(temp), writeErr)
		}
		if verifyErr := o.verifyOwned(record, data, false); verifyErr != nil {
			return "", verifyErr
		}
		candidate = record
	}
	// A retry may have already published the requested entry before an error.
	if candidate.name == name {
		return name, nil
	}
	final := &ownedFile{name: name, info: candidate.info, complete: true}
	var publishErr error
	if o.exclusive {
		publishErr = syscall.ENOTSUP
	} else {
		publishErr = o.root.Link(candidate.name, name)
	}
	if publishErr != nil && linkUnsupported(publishErr) && len(*state) < 2 {
		file, createErr := o.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr == nil {
			final, publishErr = o.writeOpened(file, name, data)
			*state = append(*state, final)
		} else {
			publishErr = createErr
		}
	}
	if publishErr == nil {
		if verifyErr := o.verifyOwned(final, data, false); verifyErr == nil {
			for _, f := range *state {
				if f.name != name {
					o.note(o.removeOwned(f))
				}
			}
			return name, nil
		} else {
			o.note(verifyErr)
		}
	} else {
		o.note(fmt.Errorf("publication of %s: %w", o.fullPath(name), publishErr))
	}
	// Hard links alias the same inode. Verify the retained bytes again even if
	// publication reported failure; rebuild once when the shared inode changed.
	if verifyErr := o.verifyOwned(candidate, data, true); verifyErr == nil {
		o.note(fmt.Errorf("requested name unavailable; verified recovery file %s", o.fullPath(candidate.name)))
		return candidate.name, nil
	} else {
		o.note(verifyErr)
	}
	if len(*state) < 2 {
		file, temp, createErr := o.createTemp(name)
		if createErr != nil {
			return "", createErr
		}
		record, writeErr := o.writeOpened(file, temp, data)
		*state = append(*state, record)
		if writeErr == nil {
			writeErr = o.verifyOwned(record, data, false)
		}
		if writeErr == nil {
			o.note(fmt.Errorf("publication verification failed; rebuilt verified recovery file %s", o.fullPath(temp)))
			return temp, nil
		}
		return "", writeErr
	}
	return "", fmt.Errorf("publication verification failed; retained files are unverified")
}
func (o *outputTarget) saveIdentity(identity *Identity, matcher addressMatcher, privateExports bool) saveResult {
	result := saveResult{}
	if err := validateIdentityConsistency(identity); err != nil {
		result.internal = true
		result.cause = err
		return result
	}
	if !matcher.matches(identity.Address[:]) {
		result.internal = true
		result.cause = fmt.Errorf("save gate: winner does not match requested pattern")
		return result
	}
	var data [identityPrivateKeySize]byte
	defer wipeBytes(data[:])
	copy(data[:32], identity.X25519Private[:])
	copy(data[32:], identity.Ed25519Seed[:])
	saved, err := o.persist(o.name, data[:], &o.retained)
	result.cause = err
	o.note(err)
	if saved != "" {
		result.Verified = append(result.Verified, o.fullPath(saved))
		o.note(o.syncDirectory())
		if saved == o.name {
			if err := o.writeIdentityInfo(identity, privateExports); err != nil {
				o.note(fmt.Errorf("identity was saved; metadata could not be saved: %w", err))
			}
		} else {
			o.note(fmt.Errorf("recovery identity has no sidecar; inspect the verified recovery file"))
		}
	}
	for _, f := range o.retained {
		if f.name == saved {
			continue
		}
		_, statErr := o.root.Lstat(f.name)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if f.complete && o.verifyOwned(f, data[:], true) == nil {
			if saved == "" {
				o.note(fmt.Errorf("verified recovery file %s has no sidecar", o.fullPath(f.name)))
			}
			result.Verified = appendUnique(result.Verified, o.fullPath(f.name))
		} else {
			result.Unverified = appendUnique(result.Unverified, o.fullPath(f.name))
		}
	}
	if locationErr := o.checkLocation(); locationErr != nil {
		result.LocationChanged = true
		o.note(locationErr)
	}
	result.Deviations = append([]string(nil), o.deviations...)
	return result
}

// Metadata is written after the identity. Incomplete metadata is removed only
// when it is still this process's entry; failures report any retained name.
func (o *outputTarget) writeFile(name string, data []byte, mode os.FileMode, preserve bool) error {
	var state []*ownedFile
	saved, err := o.persist(name, data, &state)
	if err == nil && saved == name {
		return nil
	}
	if preserve && saved != "" {
		return &recoverableWriteError{target: name, recoveryPath: o.fullPath(saved), cause: err}
	}
	for _, f := range state {
		if cleanupErr := o.removeOwned(f); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}
	if err == nil {
		err = fmt.Errorf("could not publish %s; refusing to overwrite", o.fullPath(name))
	}
	return err
}

type recoverableWriteError struct {
	target, recoveryPath string
	cause                error
}

func (e *recoverableWriteError) Error() string {
	return fmt.Sprintf("could not publish %s; verified recovery file %s: %v", e.target, e.recoveryPath, e.cause)
}
func (e *recoverableWriteError) Unwrap() error { return e.cause }
