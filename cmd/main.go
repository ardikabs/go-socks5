package main

import (
	"log/slog"
	"os"
	"os/signal"

	"github.com/ardikabs/socks5"
	"github.com/ardikabs/socks5/pkg/types"
	"github.com/go-logr/logr"
)

func main() {
	log := logr.FromSlogHandler(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	srv, err := socks5.New(socks5.ServerConfig{
		EnabledAuthMethods: []types.AuthMethod{types.AuthNoAuthRequired, types.AuthUserPass},
		Logger:             log,
	})
	if err != nil {
		log.Error(err, "failed to create server")
		os.Exit(1)
	}

	go srv.ListenAndServe("tcp", "localhost:8080")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	srv.Shutdown()
}
