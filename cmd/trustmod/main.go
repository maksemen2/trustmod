package main

import (
	"fmt"
	"os"

	"github.com/maksemen2/trustmod/internal/buildinfo"
	"github.com/maksemen2/trustmod/internal/cli"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	root := cli.NewRootCommand(buildinfo.Resolve(buildinfo.Info{
		Version: version,
		Commit:  commit,
		Date:    date,
	}))
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(cli.ExitCode(err))
	}
}
