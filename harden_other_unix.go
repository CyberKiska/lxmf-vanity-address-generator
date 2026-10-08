//go:build unix && !linux

package main

func disableDumpability() error { return nil }
