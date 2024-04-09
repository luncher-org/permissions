//go:build windows

package sid

import (
	"os/user"
	"syscall"

	"golang.org/x/sys/windows"
)

func CurrentUser() *windows.SID {
	return mustStrToSid(MustGetUser().Uid)
}

func CurrentGroup() *windows.SID {
	return mustStrToSid(MustGetUser().Gid)
}

func Everyone() *windows.SID {
	return mustGetSid(windows.WinWorldSid)
}

func BuiltinAdministrators() *windows.SID {
	return mustGetSid(windows.WinBuiltinAdministratorsSid)
}

func LocalSystem() *windows.SID {
	return mustGetSid(windows.WinLocalSystemSid)
}

func GetWellKnownSid(wellKnownType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	return mustGetSid(wellKnownType)
}

func mustStrToSid(sidStr string) *windows.SID {
	var sid *windows.SID
	sidPtr, err := syscall.UTF16PtrFromString(sidStr)
	if err != nil {
		panic(err)
	}
	err = windows.ConvertStringSidToSid(sidPtr, &sid)
	if err != nil {
		panic(err)
	}
	return sid
}

func MustGetUser() *user.User {
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}
	return currentUser
}

func mustGetSid(sidType windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	sid, err := windows.CreateWellKnownSid(sidType)
	if err != nil {
		panic(err)
	}
	return sid
}
