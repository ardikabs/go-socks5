package types

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

var (
	// NilAddress represents an empty address.
	NilAddress = &Address{
		IP:   net.IPv4zero,
		Port: int(0),
	}
)

type Address struct {
	DomainName string
	IP         net.IP
	Port       int
}

func NewAddress(r io.Reader) (*Address, error) {
	atype := make([]byte, 1)
	if _, err := r.Read(atype); err != nil {
		return nil, fmt.Errorf("failed to fetch SOCKS address type: %v", err)
	}

	address := new(Address)

	switch AddressType(atype[0]) {
	case AddressIPv4:
		ip := make([]byte, 4)
		if _, err := r.Read(ip); err != nil {
			return nil, fmt.Errorf("failed to fetch IPv4 address: %v", err)
		}
		address.IP = net.IP(ip)

	case AddressDomainName:
		domainLength := make([]byte, 1)
		if _, err := r.Read(domainLength); err != nil {
			return nil, fmt.Errorf("failed to fetch IPv4 address: %v", err)
		}

		domain := make([]byte, int(domainLength[0]))
		if _, err := io.ReadAtLeast(r, domain, int(domainLength[0])); err != nil {
			return nil, fmt.Errorf("failed to fetch domain name: %v", err)
		}

		address.DomainName = string(domain)

	case AddressIPv6:
		ip := make([]byte, 16)
		if _, err := r.Read(ip); err != nil {
			return nil, fmt.Errorf("failed to fetch IPv6 address: %v", err)
		}
		address.IP = net.IP(ip)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedAddressType, atype[0])
	}

	port := make([]byte, 2)
	if _, err := r.Read(port); err != nil {
		return nil, fmt.Errorf("failed to fetch port: %v", err)
	}

	address.Port = int(port[0])<<8 | int(port[1])
	return address, nil
}

func (a *Address) Bytes() []byte {
	var (
		atype uint8
		addr  []byte
	)

	switch {
	case a.DomainName != "":
		atype = uint8(AddressDomainName)
		addr = append([]byte{uint8(len(a.DomainName))}, a.DomainName...)
	case a.IP.To4() != nil:
		atype = uint8(AddressIPv4)
		addr = []byte(a.IP.To4())
	case a.IP.To16() != nil:
		atype = uint8(AddressIPv6)
		addr = []byte(a.IP.To16())
	}

	port := []byte{uint8(a.Port >> 8), uint8(a.Port & 0xff)}

	bytes := make([]byte, 1+len(addr)+len(port))
	bytes[0] = atype
	copy(bytes[1:], addr)
	copy(bytes[1+len(addr):], port)

	return bytes
}

func (a *Address) String() string {
	if a.DomainName != "" {
		return fmt.Sprintf("%s:%d (%s)", a.DomainName, a.Port, a.IP)
	}

	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

func (a *Address) Address() string {
	if a.IP != nil {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}

	return net.JoinHostPort(a.DomainName, strconv.Itoa(a.Port))
}
