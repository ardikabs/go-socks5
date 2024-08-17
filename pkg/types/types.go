package types

import "fmt"

// SOCKS version, which is 5
const VERSION = uint8(5)

const (
	// Authentication methods
	AuthNoAuthRequired     = AuthMethod(0)   // 0x00
	AuthGSSAPI             = AuthMethod(1)   // 0x01
	AuthUserPass           = AuthMethod(2)   // 0x02
	AuthNoAcceptableMethod = AuthMethod(255) // 0xFF
)

type AuthMethod uint8

func (a AuthMethod) String() string {
	switch a {
	case AuthNoAuthRequired:
		return fmt.Sprintf("NO AUTHENTICATION REQUIRED (%d)", a)
	case AuthGSSAPI:
		return fmt.Sprintf("GSSAPI (%d)", a)
	case AuthUserPass:
		return fmt.Sprintf("USERNAME/PASSWORD (%d)", a)
	case AuthNoAcceptableMethod:
		fallthrough
	default:
		return fmt.Sprintf("NOT ACCEPTABLE METHODS (%d)", a)
	}
}

const (
	// Address types
	AddressIPv4       = AddressType(1) // 0x01
	AddressDomainName = AddressType(3) // 0x03
	AddressIPv6       = AddressType(4) // 0x04
)

type AddressType uint8

func (a AddressType) String() string {
	switch a {
	case AddressIPv4:
		return "IPv4"
	case AddressDomainName:
		return "DOMAINNAME"
	case AddressIPv6:
		return "IPv6"
	default:
		return "unknown"
	}
}

const (
	// Reply codes
	ReplySucceeded           = ReplyCode(0) // 0x00
	ReplyGeneralFailure      = ReplyCode(1) // 0x01
	ReplyNotAllowed          = ReplyCode(2) // 0x02
	ReplyNetworkUnreach      = ReplyCode(3) // 0x03
	ReplyHostUnreach         = ReplyCode(4) // 0x04
	ReplyConnRefused         = ReplyCode(5) // 0x05
	ReplyTTLExpired          = ReplyCode(6) // 0x06
	ReplyCommandNotSupported = ReplyCode(7) // 0x07
	ReplyAddrNotSupported    = ReplyCode(8) // 0x08
)

type ReplyCode uint8

func (r ReplyCode) String() string {
	switch r {
	case ReplySucceeded:
		return "succeeded"
	case ReplyGeneralFailure:
		return "general failure"
	case ReplyNotAllowed:
		return "not allowed"
	case ReplyNetworkUnreach:
		return "network unreachable"
	case ReplyHostUnreach:
		return "host unreachable"
	case ReplyConnRefused:
		return "connection refused"
	case ReplyTTLExpired:
		return "TTL expired"
	case ReplyCommandNotSupported:
		return "command not supported"
	case ReplyAddrNotSupported:
		return "address not supported"
	default:
		return "unknown"
	}
}

const (
	// Command codes
	CommandConnect  = CommandID(1) // 0x01
	CommandBIND     = CommandID(2) // 0x02
	CommandUDPAssoc = CommandID(3) // 0x03
)

type CommandID uint8

func (c CommandID) String() string {
	switch c {
	case CommandConnect:
		return "CONNECT"
	case CommandBIND:
		return "BIND"
	case CommandUDPAssoc:
		return "UDP ASSOCIATE"
	default:
		return "unknown"
	}
}
