package authenticationkv

import (
	"fmt"
)

type KVStoreError struct {
	Issue error
}

const KVStoreErrorMessage = "KV store issue:%w"

func (e KVStoreError) Error() string {
	return fmt.Sprintf(KVStoreErrorMessage, e.Issue)
}

type ItemNotFoundError struct {
	Issue error
}

func (e ItemNotFoundError) Error() string {
	return e.Issue.Error()
}

type TransformationError struct {
	Issue error
}

func (e TransformationError) Error() string {
	return e.Issue.Error()
}
