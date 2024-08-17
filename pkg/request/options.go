package request

type Option func(*Request) error

func WithResolver(r DomainResolver) Option {
	return func(req *Request) error {
		req.resolver = r
		return nil
	}
}

func WithDialer(d Dialer) Option {
	return func(req *Request) error {
		if d == nil {
			return nil
		}

		req.dialer = d
		return nil
	}
}
