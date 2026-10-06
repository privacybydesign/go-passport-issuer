//go:build !(linux && amd64 && cgo)

package main

// engineAvailable tells readyz whether to also prove that a worker can start.
const engineAvailable = false

func newEngine() (Engine, error) { return nil, ErrEngineUnavailable }
