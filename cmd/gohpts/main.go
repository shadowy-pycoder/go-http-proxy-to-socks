package main

import (
	"fmt"
	"os"

	gohpts "github.com/shadowy-pycoder/go-http-proxy-to-socks"
)

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v (type '%s -h' for help)\n", gohpts.App, err, gohpts.App)
		os.Exit(2)
	}
}
