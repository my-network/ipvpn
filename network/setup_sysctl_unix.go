//go:build linux || darwin || freebsd || netbsd || openbsd
// +build linux darwin freebsd netbsd openbsd

package network

import (
	"fmt"
	"strconv"

	"github.com/lorenzosaino/go-sysctl"
	"github.com/xaionaro-go/errors"
)

func sysctlGetValue(key string) (intValue int64, err error) {
	defer func() { err = errors.Wrap(err) }()

	value, err := sysctl.Get(key)
	if err != nil {
		return
	}

	intValue, err = strconv.ParseInt(value, 10, 64)
	if err != nil {
		return
	}

	return
}

func sysctlIncreaseTo(key string, value int64) (err error) {
	defer func() { err = errors.Wrap(err) }()

	oldValue, err := sysctlGetValue(key)
	if err != nil {
		return fmt.Errorf(`unable to get current sysctl value by key "%v": %v`, key, err)
	}

	if value <= oldValue {
		return
	}

	err = sysctl.Set(key, strconv.FormatInt(value, 10))
	if err != nil {
		return fmt.Errorf(`unable to set sysctl value by key "%v" to "%v": %v`, key, value, err)
	}

	return
}
