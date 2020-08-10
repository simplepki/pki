package auth

import (
	"errors"

	"github.com/simplepki/pki/config"
)

type JWTAuthorizer interface {
	New() error
	AuthorizeResource(jwt string, jwtType string, resource string) (bool, error)
}

func GetJWTAuthorizer() (JWTAuthorizer, error) {
	providerString, err := config.GetAuthProvider()
	if err != nil {
		return nil, err
	}
	switch providerString {
	case "lambda":
		l := &LambdaJWTAuthorizer{}
		err = l.New()
		return l, err
	default:
		return nil, errors.New("no auth provider configured")
	}
}
