package credentials

import (
	"fmt"
)

type MemoryStore map[string]string

func (m MemoryStore) Validate(p Parameters) error {
	passwd, ok := m[p.Username]
	if !ok || passwd != p.Password {
		return fmt.Errorf("%w, either username or password is incorrect", ErrInvalidCredentials)
	}

	return nil
}
