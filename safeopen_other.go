//go:build !unix

package main

import "os"

const safeReadFlags = os.O_RDONLY
