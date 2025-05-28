package main

import (
	"fmt"
	"os"
)

func main() {
	if err := root(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v (type '%s help' for help)\n", app, err, app)
		os.Exit(2)
	}
}
