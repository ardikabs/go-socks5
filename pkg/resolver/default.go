package resolver

import (
	"context"
	"net"
)

type BaseResolver struct{}

func (d BaseResolver) Resolve(ctx context.Context, domain string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", domain)
	if err != nil {
		return nil, err
	}

	return addr.IP, nil
}
