//go:build windows

package acl

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aiyengar2/permissions/pkg/access"
	"github.com/aiyengar2/permissions/pkg/filemode"
	"github.com/aiyengar2/permissions/pkg/sid"
	"golang.org/x/sys/windows"
)

var fullControlAccessMask windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

func TestMkdir(t *testing.T) {
	defaultUser := sid.BuiltinAdministrators().String()
	defaultGroup := sid.CurrentGroup().String()

	// setup
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// check if we need to skip powershell tests
	canRunPowershell, err := getACLExists()
	if err != nil {
		t.Fatal(err)
	}

	firstACLPermissions, err := getACLPermissions(dir)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		Name      string
		Directory string

		KeepPreviousDirectory bool

		Permissions []windows.EXPLICIT_ACCESS
		// ExpectedSddl string
		ExpectedACLPermissions []aclPermission
	}{
		{
			Name: "Giving no permissions for an existing directory should use older permissions",

			KeepPreviousDirectory:  true,
			ExpectedACLPermissions: firstACLPermissions,
		},
		{
			Name: "Apply permissions on a directory that already exists",

			KeepPreviousDirectory: true,

			Permissions: []windows.EXPLICIT_ACCESS{
				access.GrantSid(fullControlAccessMask, sid.Everyone()),
				access.GrantSid(fullControlAccessMask, sid.LocalSystem()),
			},

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                "Everyone",
					Rights:            "FullControl",
				},
				{
					AccessControlType: "Allow",
					ID:                "NT AUTHORITY\\SYSTEM",
					Rights:            "FullControl",
				},
			},
		},
		{
			Name: "Create Directory With Local System and Administrators",
			Permissions: []windows.EXPLICIT_ACCESS{
				access.GrantSid(windows.GENERIC_ALL, sid.LocalSystem()),
				access.GrantSid(windows.GENERIC_ALL, sid.BuiltinAdministrators()),
			},
			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                "NT AUTHORITY\\SYSTEM",
					Rights:            "FullControl",
				},
				{
					AccessControlType: "Allow",
					ID:                "BUILTIN\\Administrators",
					Rights:            "FullControl",
				},
			},
		},
		{
			Name:                   "Giving no permissions for a new directory should yield parent permissions",
			ExpectedACLPermissions: firstACLPermissions,
		},
	}

	lastACLPermissions := firstACLPermissions
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if !tc.KeepPreviousDirectory {
				err := os.RemoveAll(dir)
				if err != nil {
					if !os.IsNotExist(err) {
						t.Error(err)
						return
					}
				}
			}

			err = Mkdir(dir, tc.Permissions...)
			if err != nil {
				t.Error(err)
				return
			}

			// If we have not defined SIDS for the DACL then
			// it's expected to just use the default ACL
			// if len(tc.Permissions) == 0 {
			// 	return
			// }

			sd, err := windows.GetNamedSecurityInfo(
				dir,
				windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
			)
			if err != nil {
				t.Error(err)
				return
			}

			t.Run("ValidateOwnerGroup", func(t *testing.T) {
				// validate owner
				owner, _, err := sd.Owner()
				if err != nil {
					t.Error(err)
					return
				}
				if owner.String() != defaultUser {
					t.Errorf("expected owner SID %s, found %s", defaultUser, owner)
					return
				}

				// validate group
				group, _, err := sd.Group()
				if err != nil {
					t.Error(err)
					return
				}
				if group.String() != defaultGroup {
					t.Errorf("expected group SID %s, found %s", defaultGroup, group)
					return
				}
			})

			t.Run("ValidateAcl", func(t *testing.T) {
				// validate permissions
				if tc.ExpectedACLPermissions == nil {
					tc.ExpectedACLPermissions = lastACLPermissions
				}
				lastACLPermissions = tc.ExpectedACLPermissions
				if !canRunPowershell {
					t.Skip("Get-Acl is not available to execute tests on this machine")
				}
				aclPermissions, err := getACLPermissions(dir)
				if err != nil {
					t.Errorf("encountered error while getting ACL: %s", err)
					return
				}
				if !reflect.DeepEqual(aclPermissions, tc.ExpectedACLPermissions) {
					t.Errorf("expected permissions %s, found %s", tc.ExpectedACLPermissions, aclPermissions)
				}
			})
		})
	}
}

func TestApply(t *testing.T) {
	user, userDomain, _, err := sid.CurrentUser().LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	currentUser := filepath.Join(userDomain, user)
	group, groupDomain, _, err := sid.CurrentGroup().LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	currentGroup := filepath.Join(groupDomain, group)

	// setup
	tempFile, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	f := tempFile.Name()
	defer os.Remove(f)

	// check if we need to skip powershell tests
	canRunPowershell, err := getACLExists()
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		Name string

		Owner       *windows.SID
		Group       *windows.SID
		Permissions []windows.EXPLICIT_ACCESS

		ExpectedACLPermissions []aclPermission
	}{
		{
			Name: "Set owner to current user",

			Owner: sid.CurrentUser(),
		},
		{
			Name: "Set group to current group",

			Group: sid.CurrentGroup(),
		},
		{
			Name: "Set 0777 permissions",

			// on an actual permissions change, the current owner and group reflect the permissions change
			Permissions: filemode.Convert(0777).ToExplicitAccess(),

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                "Everyone",
					Rights:            "Modify, Synchronize",
				},
				{
					AccessControlType: "Allow",
					ID:                currentUser,
					Rights:            "Modify, Synchronize",
				},
				{
					AccessControlType: "Allow",
					ID:                currentGroup,
					Rights:            "Modify, Synchronize",
				},
			},
		},
		{
			Name: "Set 0007 permissions",

			Permissions: filemode.Convert(0007).ToExplicitAccess(),

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                "Everyone",
					Rights:            "Modify, Synchronize",
				},
			},
		},
		{
			Name: "Set 0070 permissions",

			Permissions: filemode.Convert(0070).ToExplicitAccess(),

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                currentGroup,
					Rights:            "Modify, Synchronize",
				},
			},
		},
		{
			Name: "Set 0700 permissions",

			Permissions: filemode.Convert(0700).ToExplicitAccess(),

			ExpectedACLPermissions: []aclPermission{
				{
					AccessControlType: "Allow",
					ID:                currentUser,
					Rights:            "Modify, Synchronize",
				},
			},
		},
	}

	// set initial checks to ensure whether changes were made
	sd, err := windows.GetNamedSecurityInfo(
		f,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	lastOwner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	lastGroup, _, err := sd.Group()
	if err != nil {
		t.Fatal(err)
	}
	lastACLPermissions, err := getACLPermissions(f)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			err = Apply(f, tc.Owner, tc.Group, tc.Permissions...)
			if err != nil {
				t.Error(err)
				return
			}
			sd, err := windows.GetNamedSecurityInfo(
				f,
				windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
			)
			if err != nil {
				t.Error(err)
				return
			}

			t.Run("ValidateOwnerGroup", func(t *testing.T) {
				// validate owner
				if tc.Owner == nil {
					tc.Owner = lastOwner
				}
				lastOwner = tc.Owner
				owner, _, err := sd.Owner()
				if err != nil {
					t.Error(err)
					return
				}
				if owner.String() != tc.Owner.String() {
					t.Errorf("expected owner SID %s, found %s", tc.Owner, owner)
					return
				}

				// validate group
				if tc.Group == nil {
					tc.Group = lastGroup
				}
				lastGroup = tc.Group
				group, _, err := sd.Group()
				if err != nil {
					t.Error(err)
					return
				}
				if group.String() != tc.Group.String() {
					t.Errorf("expected group SID %s, found %s", tc.Group, group)
					return
				}
			})

			t.Run("ValidateAcl", func(t *testing.T) {
				// validate permissions
				if tc.ExpectedACLPermissions == nil {
					tc.ExpectedACLPermissions = lastACLPermissions
				}
				lastACLPermissions = tc.ExpectedACLPermissions
				if !canRunPowershell {
					t.Skip("Get-Acl is not available to execute tests on this machine")
				}
				aclPermissions, err := getACLPermissions(f)
				if err != nil {
					t.Errorf("encountered error while getting ACL: %s", err)
					return
				}
				if !reflect.DeepEqual(aclPermissions, tc.ExpectedACLPermissions) {
					t.Errorf("expected permissions %s, found %s", tc.ExpectedACLPermissions, aclPermissions)
				}
			})
		})
	}

	t.Run("Apply permissions on a file that does not exist", func(t *testing.T) {
		// create a temporary file and delete it
		tempDir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tempDir)
		f := filepath.Join(tempDir, "does-not-exist")
		// run apply on a deleted file
		err = Apply(f, sid.CurrentUser(), sid.CurrentGroup())
		if err == nil {
			t.Error("expected error")
			return
		}
		if !os.IsNotExist(err) {
			t.Error(err)
			return
		}
	})
}

type aclPermission struct {
	AccessControlType string
	ID                string
	Rights            string
}

func getACLExists() (bool, error) {
	output, err := runPowershell(`if (Get-Command Get-Acl -ErrorAction SilentlyContinue) { return $true } else { return $false }`)
	if err != nil {
		return false, err
	}
	exists := strings.Split(strings.TrimSpace(output), "\r\n")[0]
	return exists == "True", nil
}

// Note: until GetExplicitEntriesFromAcl is implemented in golang.org/x/sys/windows, which is the only recommended way to work with ACLs
// (as described in the Microsoft docs https://learn.microsoft.com/en-us/windows/win32/secauthz/getting-information-from-an-acl),
// this Go tests will have to use a workaround to directly call the `Get-Acl` powershell function to check permissions.
//
// TODO: refactor these tests once https://github.com/golang/sys/pull/84 (or a similar PR) is merged to add support for GetExplicitEntriesFromAcl
func getACLPermissions(filename string) ([]aclPermission, error) {
	output, err := runPowershell(
		fmt.Sprintf(strings.Join([]string{
			`$Path = "%s"`,
			`$acl = (Get-Acl $Path)`,
			`$acl.Access | ForEach-Object -Process {`,
			`$accessControlType = $_.AccessControlType`,
			`$id = $_.IdentityReference.Value`,
			`$rights = $_.FileSystemRights`,
			`"{0}|{1}|{2}" -f ($accessControlType), ($id), ($rights)`,
			`}`,
		}, "\r\n"), filename),
	)
	if err != nil {
		return nil, err
	}
	permissionLines := strings.Split(strings.TrimSpace(output), "\r\n")
	var permissions []aclPermission
	for _, line := range permissionLines {
		if len(line) == 0 {
			continue
		}
		lineSplit := strings.Split(line, "|")
		permissions = append(permissions, aclPermission{
			AccessControlType: lineSplit[0],
			ID:                lineSplit[1],
			Rights:            lineSplit[2],
		})
	}
	return permissions, nil
}

func runPowershell(script string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", script)
	cmd.Stderr = os.Stderr
	cmd.Stdout = &buf
	err := cmd.Run()
	return buf.String(), err
}
