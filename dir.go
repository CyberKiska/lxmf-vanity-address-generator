package main

import (
	"io"
	"os"
)

// dirOps is the output subset of os.Root; production uses rootDir only.
type dirOps interface {
	OpenFile(string, int, os.FileMode) (fileOps, error)
	Link(string, string) error
	Remove(string) error
	Lstat(string) (os.FileInfo, error)
	Stat(string) (os.FileInfo, error)
	Name() string
	Close() error
}

type fileOps interface {
	io.Reader
	io.Writer
	Stat() (os.FileInfo, error)
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

type rootDir struct{ *os.Root }

func (r rootDir) OpenFile(name string, flags int, mode os.FileMode) (fileOps, error) {
	return r.Root.OpenFile(name, flags, mode)
}
