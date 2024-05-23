//go:build windows

package acl

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/rancher/permissions/pkg/filemode"
	"golang.org/x/sys/windows"
)

// defaultChownPermissions are the default permissions applied on running a Chown operation
var defaultChownPermissions fs.FileMode = 0755

// Chown changes the owner and group of the file / directory and applies a default ACL that provides
// Owner: read, write, execute
// Group: read, execute
// Everyone: read, execute
//
// To set custom permissions, use Apply or ApplyCustom instead directly
func Chown(path string, owner *windows.SID, group *windows.SID) error {
	return Apply(path, owner, group, filemode.Convert(defaultChownPermissions).ToExplicitAccess()...)
}

// Chmod changes the file's ACL to match the provided unix permissions. It uses the file's current owner and group
// to set the ACL permissions.
func Chmod(path string, fileMode os.FileMode) error {
	return Apply(path, nil, nil, filemode.Convert(fileMode).ToExplicitAccess()...)
}

// Mkdir creates a directory with the provided permissions if it does not exist already
// If it already exists, it just applies the provided permissions
func Mkdir(path string, access ...windows.EXPLICIT_ACCESS) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	// check if directory exists in path
	_, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	exists := !os.IsNotExist(err)

	if exists {
		return apply(path, nil, nil, access...)
	}

	// use windows.CreateDirectory instead
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	args := securityArgs{
		path:   path,
		access: access,
	}
	sa, err := args.ToSecurityAttributes()
	if err != nil {
		return err
	}
	if err = windows.CreateDirectory(pathPtr, sa); err != nil {
		return err
	}
	return nil
}

// Apply performs both Chmod and Chown at the same time, where the filemode's owner and group will correspond to
// the provided owner and group (or the current owner and group, if they are set to nil)
func Apply(path string, owner *windows.SID, group *windows.SID, access ...windows.EXPLICIT_ACCESS) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}
	return apply(path, owner, group, access...)
}

// apply performs a Chmod (if owner and group are provided) and sets a custom ACL based on the provided EXPLICIT_ACCESS rules
// To create EXPLICIT_ACCESS rules, see the helper functions in pkg/access
func apply(path string, owner *windows.SID, group *windows.SID, access ...windows.EXPLICIT_ACCESS) error {
	// assemble arguments
	args := securityArgs{
		path:   path,
		owner:  owner,
		group:  group,
		access: access,
	}

	securityInfo := args.ToSecurityInfo()
	if securityInfo == 0 {
		// nothing to change
		return nil
	}
	dacl, err := args.ToDACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		securityInfo,
		owner,
		group,
		dacl,
		nil,
	)
}
