//go:build !linux
// +build !linux

package network

func FixOSSettings() error {
	return nil
}
