package auth

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/simplepki/pki/core/types"
)

type LambdaJWTAuthorizer struct {
	ARN string
}

func (l *LambdaJWTAuthorizer) New() error { return nil }

func (l *LambdaJWTAuthorizer) AuthorizeResource(jwt, jwtType, resource string) (bool, error) {
	lambdaEvent := types.AuthorizeCredentialsEvent{
		Token:     jwt,
		TokenType: jwtType,
		Resource:  resource,
	}

	jsonEvent, err := json.Marshal(&lambdaEvent)
	if err != nil {
		return false, err
	}

	lambdaInput := &lambda.InvokeInput{
		FunctionName: aws.String(l.ARN),
		Payload:      jsonEvent,
	}

	lambdaSvc := lambda.New(session.New())
	lambdaOutput, err := lambdaSvc.Invoke(lambdaInput)
	if err != nil {
		return false, err
	}

	var result bool
	err = json.Unmarshal(lambdaOutput.Payload, &result)
	if err != nil {
		return false, err
	}

	return result, nil
}
