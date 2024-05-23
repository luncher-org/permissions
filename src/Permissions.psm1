function Set-UnixPermissions {    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Path,

        [Parameter(Mandatory=$false)]
        [string]
        $Owner,

        [Parameter(Mandatory=$false)]
        [string]
        $Group,

        [Parameter(Mandatory=$false)]
        [int]
        $Mode
    )

    $exists = Test-Path $Path
    if (-not $exists) {
        throw "Cannot set permissions on path $Path if a file or directory does not exist"
    }

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $modified = $false

    if (-not [string]::IsNullOrWhiteSpace($Owner)) {
        $modified = $true
        $acl.SetOwner((New-Object System.Security.Principal.NTAccount($Owner)))
    }

    if (-not [string]::IsNullOrWhiteSpace($Group)) {
        $modified = $true
        $acl.SetGroup((New-Object System.Security.Principal.NTAccount($Group)))
    }

    if ($Mode -ne 0) {
        $modified = $true

        $acl.SetAccessRuleProtection($true, $false)

        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $acl.RemoveAccessRule($rule)
            Write-Host "Removed $rule"
        }
        Write-Host $acl.Access

        $ownerRights, $groupRights, $everyoneRights = Convert-ModeToRights $Mode

        if ($null -ne $ownerRights) {
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $acl.Owner,
                [System.Security.AccessControl.FileSystemRights]$ownerRights,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($accessRule)
        }

        if ($null -ne $groupRights) {
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $acl.Group,
                [System.Security.AccessControl.FileSystemRights]$groupRights,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($accessRule)
        }

        if ($null -ne $everyoneRights) {
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Everyone",
                [System.Security.AccessControl.FileSystemRights]$everyoneRights,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.SetAccessRule($accessRule)
        }
    }

    if ($modified) {
        Set-Acl -Path $Path -AclObject $acl
    }
}

function Convert-ModeToRights() {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [int]
        $Mode
    )

    $permissionMap = @{
        '1' = [System.Security.AccessControl.FileSystemRights]::ExecuteFile -bor `
        [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor `
        [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor `
        [System.Security.AccessControl.FileSystemRights]::Synchronize
        
        '2' = [System.Security.AccessControl.FileSystemRights]::Write -bor `
        [System.Security.AccessControl.FileSystemRights]::Delete -bor `
        [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor `
        [System.Security.AccessControl.FileSystemRights]::Synchronize
        
        '3' = [System.Security.AccessControl.FileSystemRights]::ExecuteFile -bor `
        [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor `
        [System.Security.AccessControl.FileSystemRights]::Write -bor `
        [System.Security.AccessControl.FileSystemRights]::Delete -bor `
        [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor `
        [System.Security.AccessControl.FileSystemRights]::Synchronize

        '4' = [System.Security.AccessControl.FileSystemRights]::Read -bor `
        [System.Security.AccessControl.FileSystemRights]::Synchronize

        '5' = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor `
        [System.Security.AccessControl.FileSystemRights]::Synchronize

        '6' = [System.Security.AccessControl.FileSystemRights]::Write -bor `
        [System.Security.AccessControl.FileSystemRights]::Delete -bor `
        [System.Security.AccessControl.FileSystemRights]::Read -bor `
        [System.Security.AccessControl.FileSystemRights]::Synchronize

        '7' = [System.Security.AccessControl.FileSystemRights]::Modify -bor `
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    }

    $modeSplit = $Mode.ToString()
    $ownerUnixRights = $modeSplit[-3]
    $groupUnixRights = $modeSplit[-2]
    $everyoneUnixRights = $modeSplit[-1]

    $ownerRights = $permissionMap["$ownerUnixRights"]
    $groupRights = $permissionMap["$groupUnixRights"]
    $everyoneRights = $permissionMap["$everyoneUnixRights"]

    return $ownerRights, $groupRights, $everyoneRights
}
