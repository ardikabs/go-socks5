package credentials

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type FileStore struct {
	mem MemoryStore
}

func NewFileStore(filename string) (*FileStore, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	stash := make(map[string]string)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")

		if len(parts) != 2 {
			continue
		}

		stash[parts[0]] = parts[1]
	}

	if len(stash) == 0 {
		return nil, fmt.Errorf("no credentials found or credential has invalid format (valid format 'username:password') in %s", filename)
	}

	return &FileStore{stash}, nil
}

func (f *FileStore) Validate(p Parameters) error {
	return f.mem.Validate(p)
}
