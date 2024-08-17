package types

import "fmt"

var (
	ErrRequestHeaderParseFailed       = fmt.Errorf("failed to fetch SOCKS request header")
	ErrUnsupportedVersion             = fmt.Errorf("unsupported SOCKS version")
	ErrUnsupportedUserPassAuthVersion = fmt.Errorf("unsupported user/pass auth version")
	ErrUnsupportedCommand             = fmt.Errorf("unsupported command")
	ErrUnsupportedAddressType         = fmt.Errorf("unsupported address type")
)
