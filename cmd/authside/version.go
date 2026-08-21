package main

import (
	"fmt"
	"io"
	"runtime/debug"
)

// version is the release version, injected at link time by the release
// build (goreleaser's ldflags, and the Dockerfile's AUTHSIDE_VERSION build
// arg). It stays "dev" for an ordinary `go build` or `go run`.
//
// It is deliberately not the only source: see resolveVersion.
var version = "dev"

// devVersion is the value that means "nothing was injected here".
const devVersion = "dev"

// resolveVersion reports the version to print, preferring an injected
// value and falling back to the module version Go itself recorded.
//
// The fallback matters because there are two ways to get a real authside
// binary and only one of them goes through the release pipeline:
// `go install github.com/mackee/authside/cmd/authside@v1.2.3` involves no
// ldflags at all, but Go stamps the module version into the binary, and
// debug.ReadBuildInfo can read it back. Without this, that perfectly
// legitimate install would report "dev" and be indistinguishable from a
// working-copy build.
//
// A plain `go build` in a checkout has neither: ReadBuildInfo reports the
// main module version as "(devel)", which is no more informative than
// "dev", so it is left alone.
func resolveVersion() string {
	if version != devVersion && version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return devVersion
}

// printVersion writes the resolved version to w, as one bare line. It goes
// to stdout rather than the log stream because a version is data a script
// reads (`authside --version`), not a diagnostic.
func printVersion(w io.Writer) error {
	_, err := fmt.Fprintln(w, resolveVersion())
	return err
}
