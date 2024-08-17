package auth

import (
	"github.com/ardikabs/socks5/pkg/auth/credentials"
	"github.com/ardikabs/socks5/pkg/tool/slice"
	"github.com/ardikabs/socks5/pkg/types"
)

func authFactory(enabledMethods []types.AuthMethod, offeredMethods []byte, cs credentials.Storer) Authenticator {
	for _, e := range enabledMethods {
		if !slice.In(byte(e), offeredMethods) {
			continue
		}

		switch e {
		case types.AuthNoAuthRequired:
			return &guestAuthenticator{}
		case types.AuthUserPass:
			return &userPassAuthenticator{cs: cs}
		}
	}

	return &notAcceptableAuthenticator{offeredMethods}
}
