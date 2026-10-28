// Command patchsense downloads the GitHub Release binary for this module
// version and runs it. It does not compile the Rust crate.
//
// patchsenseVersion is the module version. It is not read from the environment,
// so the downloaded tag always matches this package.
// PATCHSENSE_RELEASE_BASE overrides the release download prefix (tests).
// PATCHSENSE_CACHE_DIR overrides the cache directory.
// PATCHSENSE_TARGET overrides target detection (tests, or a wrong libc guess).
package main

import (
	"fmt"
	"os"
)

const patchsenseVersion = "0.1.0"

func main() {
	code, err := launch(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "patchsense: %s\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func launch(args []string) (int, error) {
	triple, exe, err := detectTarget()
	if err != nil {
		return 0, err
	}
	cache, err := cachePath(triple, exe)
	if err != nil {
		return 0, err
	}
	if _, statErr := os.Stat(cache); statErr != nil {
		if err := installBinary(triple, exe, cache); err != nil {
			return 0, err
		}
	}
	return execBinary(cache, args)
}
