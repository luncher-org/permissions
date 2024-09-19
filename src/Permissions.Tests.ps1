BeforeAll {
    Import-Module -Name @(
        "$PSScriptRoot\testutils.psm1",
        "$PSScriptRoot\Permissions.psm1"
    ) -WarningAction Ignore -Force    

    # Add security module
    Import-Module Microsoft.PowerShell.Security

    # Defaults
    $tempFile = New-TemporaryFile
    $DefaultOwner, $DefaultGroup, $DefaultPermissions = Get-Permissions $tempFile.FullName
    Remove-Item -Path $tempFile.FullName -Force

    # Constants
    $RestrictedOwner = Get-CurrentUser
    $RestrictedGroup = "BUILTIN\Administrators"
    $RestrictedFileMode = 0600
    $RestrictedFilePermissions = @(  
        [PSCustomObject]@{
            AccessMask = [System.Security.AccessControl.FileSystemRights]::Write -bor `
            [System.Security.AccessControl.FileSystemRights]::Delete -bor `
            [System.Security.AccessControl.FileSystemRights]::Read -bor `
            [System.Security.AccessControl.FileSystemRights]::Synchronize
            Type = 0
            Identity = $RestrictedOwner
        }
    )
    $RestrictedDirectoryMode = 0755
    $RestrictedDirectoryPermissions = @(  
        [PSCustomObject]@{
            AccessMask = [System.Security.AccessControl.FileSystemRights]::Modify -bor `
            [System.Security.AccessControl.FileSystemRights]::Synchronize
            Type = 0
            Identity = $RestrictedOwner
        }
        [PSCustomObject]@{
            AccessMask = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor `
            [System.Security.AccessControl.FileSystemRights]::Synchronize
            Type = 0
            Identity = $RestrictedGroup
        }
        [PSCustomObject]@{
            AccessMask = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor `
            [System.Security.AccessControl.FileSystemRights]::Synchronize
            Type = 0
            Identity = "Everyone"
        }
    )
}

Describe "Set-UnixPermissions" {

    Context "when parameter Path is the only parameter provided" {
        It "should fail if the file does not exist" {
            { Set-UnixPermissions -Path "does-not-exist" } | Should -Throw 'Cannot set permissions on path does-not-exist if a file or directory does not exist'
        }
        It "should set default permissions if file exists" {
            try {
                $tempFile = New-TemporaryFile
                Set-UnixPermissions -Path $tempFile.FullName
                Test-Permissions -Path $tempFile -ExpectedOwner $DefaultOwner -ExpectedGroup $DefaultGroup -ExpectedPermissions $DefaultPermissions
            } catch {
                throw $_
            } finally {
                Remove-Item -Path $tempFile.FullName -Force
            }
        }
        It "should set default permissions if directory exists" {
            try {
                $tempDir = New-TemporaryDirectory
                Set-UnixPermissions -Path $tempDir
                Test-Permissions -Path $tempDir -ExpectedOwner $DefaultOwner -ExpectedGroup $DefaultGroup -ExpectedPermissions $DefaultPermissions
            } catch {
                throw $_
            } finally {
                Remove-Item -Path $tempDir -Force
            }
        }
    }

    Context "when other parameters are provided" {
        It "should set owner to current user only" {
            try {
                $tempFile = New-TemporaryFile
                Set-UnixPermissions -Path $tempFile.FullName -Owner $RestrictedOwner
                Test-Permissions -Path $tempFile -ExpectedOwner $RestrictedOwner -ExpectedGroup $DefaultGroup -ExpectedPermissions $DefaultPermissions
            } catch {
                throw $_
            } finally {
                Remove-Item -Path $tempFile.FullName -Force
            }
        }
        It "should set group to admin only" {
            try {
                $tempFile = New-TemporaryFile
                Set-UnixPermissions -Path $tempFile.FullName -Group $RestrictedGroup
                Test-Permissions -Path $tempFile -ExpectedOwner $DefaultOwner -ExpectedGroup $RestrictedGroup -ExpectedPermissions $DefaultPermissions
            } catch {
                throw $_
            } finally {
                Remove-Item -Path $tempFile.FullName -Force
            }
        }
        It "should set permissions on file to user or admin only" {
            try {
                $tempFile = New-TemporaryFile
                Set-UnixPermissions -Path $tempFile.FullName -Owner $RestrictedOwner -Group $RestrictedGroup -Mode $RestrictedFileMode
                Test-Permissions -Path $tempFile -ExpectedOwner $RestrictedOwner -ExpectedGroup $RestrictedGroup -ExpectedPermissions $RestrictedFilePermissions
            } catch {
                throw $_
            } finally {
                Remove-Item -Path $tempFile.FullName -Force
            }
        }
        It "should set permissions on directory to user or admin only" {
            try {
                $tempDir = New-TemporaryDirectory
                Set-UnixPermissions -Path $tempDir -Owner $RestrictedOwner -Group $RestrictedGroup -Mode $RestrictedDirectoryMode
                Test-Permissions -Path $tempDir -ExpectedOwner $RestrictedOwner -ExpectedGroup $RestrictedGroup -ExpectedPermissions $RestrictedDirectoryPermissions
            } catch {
                throw $_
            } finally {
                Remove-Item -Path $tempDir -Force
            }
        }
    }
}