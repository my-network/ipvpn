//go:build linux
// +build linux

package network

import "github.com/hashicorp/go-multierror"

func FixOSSettings() error {
	sysctlRequiredValues := map[string]int64{
		"net.core.rmem_max": 256 * 1024 * 1024,
	}

	var err error
	for k, v := range sysctlRequiredValues {
		addErr := sysctlIncreaseTo(k, v)
		if addErr != nil {
			err = multierror.Append(err, addErr)
		}
	}
	return err
}
