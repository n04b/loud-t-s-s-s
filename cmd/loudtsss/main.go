// Command loudtsss manages a typed environment config with per-environment encrypted values.
package main

import (
	"fmt"
	"os"

	"github.com/n04b/loud-t-s-s-s/internal/loudtsss"
)

func main() {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	os.Exit(loudtsss.Main(os.Args[1:], os.Stdout, os.Stderr, os.Getenv, wd))
}
