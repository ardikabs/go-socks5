package socks5

import (
	"github.com/ardikabs/socks5/pkg/auth/credentials"
	"github.com/ardikabs/socks5/pkg/request"
	"github.com/ardikabs/socks5/pkg/types"
	"github.com/go-logr/logr"
)

// ServerConfig is a configuration for the server.
type ServerConfig struct {
	// EnabledAuthMethods is a list of authentication methods that the server supports.
	// Order of the methods is important, the server will choose the first method that the client supports.
	// It defaults to [types.AuthNoAuthRequired, types.AuthUserPass].
	EnabledAuthMethods []types.AuthMethod

	// CredentialStore is a store for the server to validate the client's credentials.
	CredentialStore credentials.Storer

	// Logger is a logger for the server to log messages.
	Logger logr.Logger

	// Dialer is a custom dialer for the server to establish connection to the target host.
	Dialer request.Dialer

	// UserPassMaps is a map of username and password, used for USERNAME/PASSWORD auth method.
	// Mutual exclusive with UserPassFilename, UserPassFilename will take precedence if both are set.
	UserPassMaps map[string]string

	// UserPassFilename is a filename that contains the username and password, used for USERNAME/PASSWORD auth method.
	// Mutual exclusive with UserPassMaps, UserPassFilename will take precedence if both are set.
	UserPassFilename string
}
