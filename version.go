package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

var version = "dev"

func buildVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}
func versionText() string {
	return fmt.Sprintf("lxmf-vanity %s (%s %s/%s)\n", buildVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
