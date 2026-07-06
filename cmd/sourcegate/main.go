package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sourcegate/sourcegate/internal/app"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client := &http.Client{Timeout: 10 * time.Second}
	sourcegate := app.New(client, os.Stdout, os.Stderr)

	result, err := sourcegate.Run(ctx, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if result.ExitCode == 0 {
			os.Exit(app.ExitOperationalError)
		}
		os.Exit(result.ExitCode)
	}
	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}
}
