package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sourcegate/sourcegate/internal/sourcegate"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 10 * time.Second}
	app := sourcegate.NewApp(client, os.Stdout, os.Stderr)

	if err := app.Run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
