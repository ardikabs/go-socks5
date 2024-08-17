package credentials

import "fmt"

var (
	ErrInvalidCredentials = fmt.Errorf("invalid credentials")
)

type Storer interface {
	Validate(Parameters) error
}

type Parameters struct {

	// Parameters used for USERNAME/PASSWORD authentication.
	Username string
	Password string
}
