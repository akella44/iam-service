package repository

import "errors"

var (
	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("repository: not found")
	// ErrNotImplemented signals the operation is not yet implemented for the chosen backend.
	ErrNotImplemented = errors.New("repository: not implemented")
)
