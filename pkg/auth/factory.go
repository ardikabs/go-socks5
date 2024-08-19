package auth

import (
	"github.com/ardikabs/socks5/pkg/auth/credentials"
	"github.com/ardikabs/socks5/pkg/tool/slice"
	"github.com/ardikabs/socks5/pkg/types"
)

func factory(enabledMethods []types.AuthMethod, offeredMethods []byte, cs credentials.Storer) (types.AuthMethod, Authenticator) {
	for _, e := range enabledMethods {
		if !slice.In(byte(e), offeredMethods) {
			continue
		}

		switch e {
		case types.AuthNoAuthRequired:
			return e, &guestAuthenticator{}
		case types.AuthUserPass:
			return e, &userPassAuthenticator{cs: cs}
		}
	}

	return types.AuthNoAcceptableMethod, &notAcceptableAuthenticator{offeredMethods}
}
