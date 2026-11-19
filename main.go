package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/OJ/gobuster/v3/cli/dir"
	"github.com/OJ/gobuster/v3/cli/dns"
	"github.com/OJ/gobuster/v3/cli/fuzz"
	"github.com/OJ/gobuster/v3/cli/gcs"
	"github.com/OJ/gobuster/v3/cli/s3"
	"github.com/OJ/gobuster/v3/cli/tftp"
	"github.com/OJ/gobuster/v3/cli/vhost"
	"github.com/OJ/gobuster/v3/libgobuster"
	"github.com/urfave/cli/v2"

	"go.uber.org/automaxprocs/maxprocs"
)

func main() {
	if _, err := maxprocs.Set(); err != nil {
		fmt.Printf("Error on gomaxprocs: %v\n", err) // nolint forbidigo
	}

	cli.VersionPrinter = func(_ *cli.Context) {
		fmt.Printf("gobuster version %s\n", libgobuster.VERSION) // nolint:forbidigo
		if info, ok := debug.ReadBuildInfo(); ok {
			fmt.Printf("Build info:\n") // nolint forbidigo
			fmt.Printf("%s", info)      // nolint forbidigo
		}
	}

	app := &cli.App{
		Name:      "gobuster",
		Usage:     "the tool you love",
		UsageText: "gobuster command [command options]",
		Authors: []*cli.Author{
			{
				Name: "Christian Mehlmauer (@firefart)",
			},
			{
				Name: "OJ Reeves (@TheColonial)",
			},
		},
		Version: libgobuster.GetVersion(),
		Commands: []*cli.Command{
			dir.Command(),
			vhost.Command(),
			dns.Command(),
			fuzz.Command(),
			tftp.Command(),
			s3.Command(),
			gcs.Command(),
		},
	}

	// A first interrupt cancels the run context so workers stop at a safe
	// point and the stable output of the completed part is rendered. A second
	// interrupt restores the default hard termination.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := app.RunContext(ctx, os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
