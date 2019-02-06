function ArtifactCollector {
    <#
    .SYNOPSIS
        Collects artifacts for cyber assessments.
    .DESCRIPTION
        Collects artifacts for cyber assessments.
        - Active Directory Subnets, Computers, Users, Groups, Group Policies, and OUs
        - PDQ Inventory database
        - Endpoint Security logs
        - WiFi Profiles
    .EXAMPLE
        ArtifactCollector
        Collects all artifacts and zips them into an archive for transport.
    .INPUTS
        None
    .OUTPUTS
        System.Object
    .NOTES
        #######################################################################################
        Author:     Jason Adsit
        Version:    1.0
        #######################################################################################
        License:    https://github.com/jasonadsit/ArtifactCollector/blob/master/LICENSE
        #######################################################################################
    .LINK
        https://jasonadsit.github.io
    .LINK
        https://github.com/jasonadsit/ArtifactCollector
    .FUNCTIONALITY
        Collects artifacts for cyber assessments using native tools.
        No out-of-box PowerShell modules are required.
        - Active Directory Subnets, Computers, Users, Groups, and Group Policies
        - PDQ Inventory database
        - Endpoint Security logs
    #>
    [CmdletBinding()]
    param () #param
    begin {
        $GlobalStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $PowVer = $PSVersionTable.PSVersion.Major
    } #begin
    process {
        ### region Prep ###
        $DomainJoined = (Get-CimInstance -ClassName CIM_ComputerSystem).PartOfDomain
        $Domain = [string]([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name)
        $Domain = $Domain.ToUpper()
        $ArtifactDir = "$env:USERPROFILE\Downloads\Artifacts_$Domain`_$(Get-Date -Format yyyyMMdd_hhmm)"
        $ArtifactFile = "$ArtifactDir.zip"
        New-Item -Path $ArtifactDir -ItemType Directory -Force | Out-Null
        Push-Location -Path $ArtifactDir
        ### endregion Prep ###
        ### region AD ###
        $Subnets = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Subnets |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Subnet = [string]$_.Name
                Site = [string]$_.Site
                Location = [string]$_.Location
            }
            $Params = @{
                Activity = 'Active Directory: Enumerating Subnets'
                Status = "Now Processing: $([string]$_.Name)"
            }
            Write-Progress @Params
        }
        $Computers = ([adsisearcher]"(objectClass=computer)").FindAll() |
        ForEach-Object {
            [pscustomobject][ordered]@{
                ComputerName = [string]$_.Properties.name
                OperatingSystem = [string]$_.Properties.operatingsystem
                Description = [string]$_.Properties.description
            }
            $Params = @{
                Activity = 'Active Directory: Enumerating Computers'
                Status = "Now Processing: $([string]$_.Properties.name)"
            }
            Write-Progress @Params
        }
        $Users = ([adsisearcher]"(&(objectCategory=person)(objectClass=user))").FindAll() |
        ForEach-Object {
            $SamAccountName = [string]$_.Properties.samaccountname
            $objAct = New-Object System.Security.Principal.NTAccount("$SamAccountName")
            $objSID = $objAct.Translate([System.Security.Principal.SecurityIdentifier])
            $SID = [string]$objSID.Value
            $MemberOf = [string[]]$_.Properties.memberof | ForEach-Object {
                if ($_ -match 'LDAP://') {
                    $_.Replace('LDAP://','')
                }
            }
            [pscustomobject][ordered]@{
                SamAccountName = $SamAccountName
                UserPrincipalName = [string]$_.Properties.userprincipalname
                SID = $SID
                MemberOf = $MemberOf
            }
            $Params = @{
                Activity = 'Active Directory: Enumerating Users'
                Status = "Now Processing: $([string]$_.Properties.samaccountname)"
            }
            Write-Progress @Params
        }
        $Groups = ([adsisearcher]"(objectCategory=group)").FindAll() |
        ForEach-Object {
            [pscustomobject][ordered]@{
                SamAccountName = [string]$_.Properties.samaccountname
                Description = [string]$_.Properties.description
                Path = [string]$_.Properties.adspath
            }
            $Params = @{
                Activity = 'Active Directory: Enumerating Groups'
                Status = "Now Processing: $([string]$_.Properties.samaccountname)"
            }
            Write-Progress @Params
        }
        $GroupPolicies = ([adsisearcher]"(objectCategory=groupPolicyContainer)").FindAll() |
        ForEach-Object {
            $GpFsPath = [string]$_.Properties.gpcfilesyspath
            $GpGuid = Split-Path -Path $GpFsPath -Leaf
            [pscustomobject][ordered]@{
                Name = [string]$_.Properties.displayname
                Path = $GpFsPath
                Guid = $GpGuid
            }
            $Params = @{
                Activity = 'Active Directory: Enumerating Group Policies'
                Status = "Now Processing: $([string]$_.Properties.displayname)"
            }
            Write-Progress @Params
        }
        if ($PowVer -ge 5) {
            $GpHt = $GroupPolicies | Group-Object -Property Guid -AsHashTable
        } elseif ($PowVer -lt 5) {
            $GpHt = $GroupPolicies | Group-Object -Property Guid | ForEach-Object { @{ $_.Name = $_.Group.Name } }   
        }
        $OUs = ([adsisearcher]"(objectCategory=organizationalUnit)").FindAll() |
        ForEach-Object {
            $GpLink = [string]$_.Properties.gplink
            if ($GpLink -match 'LDAP://cn=') {
                $LinkedGPOs = $_.Properties.gplink.Split('][') | ForEach-Object {
                    $Guid = $_.Split(';')[0].Trim('[').Split(',')[0] -ireplace 'LDAP://cn=',''
                    $Name = $GpHt[$Guid].Name
                    $EnforcedString = [string]$_.Split(';')[-1].Trim(']')
                    $EnforcedInt = [int]$EnforcedString
                    if ($EnforcedInt -eq 0) {
                        $Enforced = $false
                    } elseif ($EnforcedInt -eq 1) {
                        $Enforced = $true
                    }
                    [pscustomobject][ordered]@{
                        Name = $Name
                        Guid = $Guid
                        Enforced = $Enforced
                    }
                }
            } elseif (-not $GpLink) {
                $LinkedGPOs = $null
            }
            $BlockedInheritanceString = [string]$_.Properties.gpoptions
            $BlockedInheritanceInt = [int]$BlockedInheritanceString
            if ($BlockedInheritanceInt -eq 0) {
                $BlockedInheritance = $false
            } elseif ($BlockedInheritanceInt -eq 1) {
                $BlockedInheritance = $true
            }
            [pscustomobject][ordered]@{
                Name = [string]$_.Properties.name
                DistinguishedName = [string]$_.Properties.distinguishedname
                LinkedGPOs = $LinkedGPOs
                BlockedInheritance = $BlockedInheritance
            }
            $Params = @{
                Activity = 'Active Directory: Enumerating OUs'
                Status = "Now Processing: $([string]$_.Properties.name)"
            }
            Write-Progress @Params
        }
        $AdInfo = [pscustomobject][ordered]@{
            Domain = $Domain
            Subnets = $Subnets
            Computers = $Computers
            Users = $Users
            Groups = $Groups
            GroupPolicies = $GroupPolicies
            OUs = $OUs
        }
        $AdInfo | Export-Clixml -Path .\ActiveDirectory.xml
        ### endregion AD ###
        ### region GPO ###
        $DirName = 'GPO'
        New-Item -Path .\$DirName -ItemType Directory | Out-Null
        $AdInfo.GroupPolicies | Get-Item |
        ForEach-Object {
            $_ | Copy-Item -Recurse -Destination .\$DirName\ -ErrorAction SilentlyContinue
            $Params = @{
                Activity = 'Active Directory: Copying GPOs'
                Status = "Now Processing: $($GpHt[$($_.Name)].Name)"
            }
            Write-Progress @Params
        }
        ### endregion GPO ###
        ### region PDQ ###
        Remove-Variable -Name DirName
        $DirName = 'PDQ'
        $PdqDb = "$env:ProgramData\Admin Arsenal\PDQ Inventory\Database.db"
        $PdqPath = Resolve-Path -Path $PdqDb -ErrorAction SilentlyContinue
        if ($PdqPath) {
            New-Item -Path .\$DirName -ItemType Directory | Out-Null
            $ErrorActionPreferenceBak = $ErrorActionPreference
            $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
            try {
                $PdqPath | Get-Item | Copy-Item -Destination .\$DirName\
            } catch {
                try {
                    $PdqDbBackup = "$env:ProgramData\Admin Arsenal\PDQ Inventory\Backups\Database.*.db.cab"
                    Resolve-Path -Path $PdqDbBackup -ErrorAction SilentlyContinue |
                    Get-Item | Sort-Object -Property LastWriteTime | Select-Object -Last 1 |
                    Copy-Item -Destination .\$DirName\
                } catch {}
            }
            $ErrorActionPreference = $ErrorActionPreferenceBak
        }
        ### endregion PDQ ###
        ### region Sophos ###
        Remove-Variable -Name DirName
        $DirName = 'Sophos'
        $Sophos = New-Object -TypeName System.Collections.ArrayList
        $SophosPath = "$env:ProgramData\Sophos"
        $SophosNtp = Resolve-Path -Path "$SophosPath\Sophos Network Threat Protection\Logs\SntpService.log" -ErrorAction SilentlyContinue
        $SophosAv = Resolve-Path -Path "$SophosPath\Sophos Anti-Virus\Logs\SAV.txt" -ErrorAction SilentlyContinue
        $SophosNtp | ForEach-Object { [void]$Sophos.Add($_) }
        $SophosAv | ForEach-Object { [void]$Sophos.Add($_) }
        if ($Sophos) {
            New-Item -Path .\$DirName -ItemType Directory | Out-Null
            $Sophos | Get-Item | ForEach-Object {
                $_ | Copy-Item -Destination .\$DirName\
                $Params = @{
                    Activity = 'Sophos: Gathering Logs'
                    Status = "Now Processing: $($_.Name)"
                }
                Write-Progress @Params
            }
        }
        ### endregion Sophos ###
        ### region Symantec ###
        Remove-Variable -Name DirName
        $DirName = 'Symantec'
        $Symantec = New-Object -TypeName System.Collections.ArrayList
        $SepLogPath = "$env:ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs"
        $SepSecLog = Resolve-Path -Path "$SepLogPath\seclog.log" -ErrorAction SilentlyContinue
        $SepTraLog = Resolve-Path -Path "$SepLogPath\tralog.log" -ErrorAction SilentlyContinue
        $SepSecLog | ForEach-Object { [void]$Symantec.Add($_) }
        $SepTraLog | ForEach-Object { [void]$Symantec.Add($_) }
        if ($Symantec) {
            New-Item -Path .\$DirName -ItemType Directory | Out-Null
            $Symantec | Get-Item | ForEach-Object {
                $_ | Copy-Item -Destination .\$DirName\
                Write-Progress -Activity 'Symantec: Gathering Logs' -Status "Now Processing: $($_.Name)"
            }
        }
        ### region Symantec ###
        ### region McAfee ###
        Remove-Variable -Name DirName
        $DirName = 'McAfee'
        $McAfee = Resolve-Path -Path "$env:ProgramData\McAfee\Host Intrusion Prevention\HipShield.log*" -ErrorAction SilentlyContinue
        if ($McAfee) {
            New-Item -Path .\$DirName -ItemType Directory | Out-Null
            $McAfee | Get-Item | ForEach-Object {
                $_ | Copy-Item -Destination .\$DirName\
                Write-Progress -Activity 'McAfee: Gathering Logs' -Status "Now Processing: $($_.Name)"
            }
        }
        ### endregion McAfee ###
        ### region WiFi ###
        Remove-Variable -Name DirName
        $DirName = 'WiFi'
        $Netsh = 'C:\Windows\System32\netsh.exe'
        $NetshParams = 'wlan show profiles'
        $Params = @{
            FilePath = $Netsh
            ArgumentList = $NetshParams
            NoNewWindow = $true
            Wait = $true
        }
        $WiFiProfiles = Start-Process @Params | Select-String -Pattern '\ :\ '
        if ($WiFiProfiles) {
            New-Item -Path .\$DirName -ItemType Directory | Out-Null
            $WiFiProfiles = $WiFiProfiles | ForEach-Object {
                $_.ToString().Split(':')[-1].Trim()
            }
            $WiFiProfiles | ForEach-Object {
                $NetshParams = "wlan export profile name=`"$_`" folder=`".\$DirName`" key=clear"
                $Params = @{
                    FilePath = $Netsh
                    ArgumentList = $NetshParams
                    NoNewWindow = $true
                    Wait = $true
                }
                Start-Process @Params | Out-Null
            }
        }
        ### endregion WiFi ###
        ### region ZIP ###
        if ($PowVer -ge 5) {
            Compress-Archive -Path $ArtifactDir -DestinationPath $ArtifactDir
        } elseif (($PowVer -lt 5) -and ($PowVer -gt 2)) {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $Compression = [System.IO.Compression.CompressionLevel]::Optimal
            $Archive = [System.IO.Compression.ZipFile]::Open($ArtifactFile,"Update")
            Get-ChildItem -Path .\ -Recurse -File -Force |
            Select-Object -ExpandProperty FullName | ForEach-Object {
                $RelPath = (Resolve-Path -Path $_ -Relative).TrimStart(".\")
                $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($Archive,$_,$RelPath,$Compression)
                $EachFile = Split-Path -Path $_ -Leaf
                $Params = @{
                    Activity = 'Archive: Zipping Artifact Folder'
                    Status = "Now Processing: $EachFile"
                }
                Write-Progress @Params
            }
            $Archive.Dispose()
        } elseif ($PowVer -le 2) {
            Set-Content -Path $ArtifactFile -Value ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))
            $ShellApp = New-Object -ComObject Shell.Application
            $ArtifactZip = Get-Item -Path $ArtifactFile
            $ArtifactZip.IsReadOnly = $false
            $ShellZip = $ShellApp.NameSpace($ArtifactZip.FullName)
            $ShellZip.CopyHere($ArtifactDir)
            Start-Sleep -Seconds 2
        }
        ### endregion ZIP ###
        Pop-Location
    } #process
    end {
        $GlobalStopwatch.Stop()
        $Seconds = $GlobalStopwatch.Elapsed.Seconds
        $ArtifactZip = Get-Item -Path $ArtifactFile
        [pscustomobject][ordered]@{
            Name = (Split-Path -Path $ArtifactZip.FullName -Leaf)
            Size = "$([math]::Round($(($ArtifactZip.Length)/1MB))) MB"
            Time = "$Seconds sec"
            Path = $ArtifactZip.FullName
            Comment = "Please arrange to get the '$($ArtifactZip.Name)' file to the cyber assessment team."
        }
    } #end
} #ArtifactCollector
ArtifactCollector