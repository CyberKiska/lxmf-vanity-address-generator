package main

import "os"

// faultDir wraps real anchored I/O. A rule can fail before or after an operation
// took effect, or shorten a read/write. It is owned by the saving goroutine.
type faultRule struct {
	op    string
	nth   int
	after bool
	short int
	err   error
}

type faultDir struct {
	dirOps
	link  func(string, string) error
	rules []faultRule
	calls map[string]int
}

func (d *faultDir) rule(op string) *faultRule {
	if d.calls == nil {
		d.calls = make(map[string]int)
	}
	d.calls[op]++
	for i := range d.rules {
		r := &d.rules[i]
		if r.op == op && (r.nth == 0 || r.nth == d.calls[op]) {
			return r
		}
	}
	return nil
}
func (d *faultDir) operation(op string, fn func() error) error {
	r := d.rule(op)
	if r != nil && !r.after {
		return r.err
	}
	err := fn()
	if r != nil {
		return r.err
	}
	return err
}
func (d *faultDir) Link(a, b string) error {
	return d.operation("link", func() error {
		if d.link != nil {
			return d.link(a, b)
		}
		return d.dirOps.Link(a, b)
	})
}
func (d *faultDir) Remove(name string) error {
	return d.operation("remove", func() error { return d.dirOps.Remove(name) })
}
func (d *faultDir) OpenFile(name string, flags int, mode os.FileMode) (fileOps, error) {
	r := d.rule("open")
	if r != nil && !r.after {
		return nil, r.err
	}
	f, err := d.dirOps.OpenFile(name, flags, mode)
	if r != nil {
		if f != nil {
			f.Close()
		}
		return nil, r.err
	}
	if err != nil {
		return nil, err
	}
	return &faultFile{fileOps: f, dir: d}, nil
}
func (d *faultDir) Lstat(name string) (os.FileInfo, error) {
	if r := d.rule("lstat"); r != nil {
		return nil, r.err
	}
	return d.dirOps.Lstat(name)
}
func (d *faultDir) Stat(name string) (os.FileInfo, error) {
	if r := d.rule("stat"); r != nil {
		return nil, r.err
	}
	return d.dirOps.Stat(name)
}

type faultFile struct {
	fileOps
	dir *faultDir
}

func (f *faultFile) Chmod(mode os.FileMode) error {
	return f.dir.operation("chmod", func() error { return f.fileOps.Chmod(mode) })
}
func (f *faultFile) Sync() error { return f.dir.operation("sync", f.fileOps.Sync) }
func (f *faultFile) Close() error {
	// Close errors must not leave test-owned OS handles open.
	r := f.dir.rule("close")
	err := f.fileOps.Close()
	if r != nil {
		return r.err
	}
	return err
}
func (f *faultFile) Stat() (os.FileInfo, error) {
	if r := f.dir.rule("fstat"); r != nil {
		return nil, r.err
	}
	return f.fileOps.Stat()
}
func (f *faultFile) Write(p []byte) (int, error) {
	r := f.dir.rule("write")
	if r != nil && !r.after {
		if r.short > 0 {
			n, _ := f.fileOps.Write(p[:min(r.short, len(p))])
			return n, r.err
		}
		return 0, r.err
	}
	n, err := f.fileOps.Write(p)
	if r != nil {
		return n, r.err
	}
	return n, err
}
func (f *faultFile) Read(p []byte) (int, error) {
	r := f.dir.rule("read")
	if r != nil && !r.after {
		if r.short > 0 {
			n, _ := f.fileOps.Read(p[:min(r.short, len(p))])
			return n, r.err
		}
		return 0, r.err
	}
	n, err := f.fileOps.Read(p)
	if r != nil {
		return n, r.err
	}
	return n, err
}
