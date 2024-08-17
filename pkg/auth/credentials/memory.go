package credentials

import (
	"fmt"
)

type InMemoryStore struct {
	stash map[string]string
}

func NewInMemoryStore(data map[string]string) (*InMemoryStore, error) {
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	return &InMemoryStore{stash: data}, nil
}

func (m *InMemoryStore) Validate(p Parameters) error {
	if passwd, ok := m.stash[p.Username]; ok && passwd != p.Password {
		return ErrInvalidCredentials
	}

	return fmt.Errorf("username %s not found", p.Username)
}
