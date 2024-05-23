function New-TemporaryDirectory {
    $tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    return $tempDir
}

function Get-CurrentUser {
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Get-Permissions {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path
    )

    $exists = Test-Path $Path
    if (-not $exists) {
        throw "Cannot set permissions on path $Path if a file or directory does not exist"
    }

    $acl = Get-Acl $Path

    $owner = $acl.Owner
    $group = $acl.Group
    $permissions = @()
    foreach ($rule in $acl.Access) {
        $permissions += [PSCustomObject]@{
            AccessMask = $rule.FileSystemRights.ToString()
            Type = $rule.AccessControlType
            Identity = $rule.IdentityReference.Value
        }
    }

    return $owner, $group, $permissions
}

function Test-Permissions {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter(Mandatory=$true)]
        [string]
        $ExpectedOwner,

        [Parameter(Mandatory=$true)]
        [string]
        $ExpectedGroup,

        [Parameter(Mandatory=$true)]
        [System.Object[]]
        $ExpectedPermissions
    )

    $owner, $group, $permissions = Get-Permissions -Path $Path

    $errors = @()

    if ($owner -ne $ExpectedOwner) {
        $errors += "expected owner $ExpectedOwner, found $owner"
    }

    if ($group -ne $ExpectedGroup) {
        $errors += "expected group $ExpectedGroup, found $group"
    }

    $notEqual = $permissions.Count -ne $ExpectedPermissions.Count

    if (-not $notEqual) {
        $comparePermissions = Compare-Object $permissions $ExpectedPermissions
        foreach ($permission in $comparePermissions) {
            if ($permission.SideIndicator -ne "=") {
                $notEqual = $true
                break
            }
        }
    }
    if ($notEqual) {
        $expected = $ExpectedPermissions | ConvertTo-Json
        $found = $permissions | ConvertTo-Json
        $errors += "expected permissions $expected, found $found"
    }

    # Check
    if ($errors.Count -gt 0) {
        $errors_joined = $errors -join "`n- "
        throw "Permissions don't match expectations:`n- $errors_joined"
    }
}
