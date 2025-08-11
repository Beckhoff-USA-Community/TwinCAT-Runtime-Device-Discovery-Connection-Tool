<#
.SYNOPSIS
    Discover TwinCAT runtime devices, via ADS broadcast search and offer connection options.
.DESCRIPTION
    This script discovers TwinCAT runtime devices on the network and provides connection options such as SSH, RDP, FTP, and WinSCP.
    It uses the TcXaeMgmt PowerShell module to perform ADS route discovery and allows users to connect to devices via various methods.
    If CERHost.exe is not present when connecting to a CE device, it will automatically download and extract it.
.PARAMETER TimeoutSeconds
    Timeout for user input in seconds.
.PARAMETER WinSCPPath
    Path to WinSCP executable.
.PARAMETER CerHostPath
    Path to CERHost executable.
.PARAMETER AdminUserName
    Administrator username for SSH and RDP connections.
.PARAMETER AdminPassword
    Administrator password for SSH and RDP connections.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$TimeoutSeconds = 10,
    [Parameter(Mandatory=$false)]
    [string]$WinSCPPath    = "C:\Program Files (x86)\WinSCP\WinSCP.exe",
    [Parameter(Mandatory=$false)]
    [string]$CerHostPath   = "$PSScriptRoot\CERHOST.exe",
    [Parameter(Mandatory=$false)]
    [string]$AdminUserName = "Administrator",
    [Parameter(Mandatory=$false)]
    [SecureString]$AdminPassword = (ConvertTo-SecureString "1" -AsPlainText -Force)
)

function Read-InputWithTimeout {
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds = 10,
        [switch]$AllowRefresh
    )
    try {
        $endTime     = (Get-Date).AddSeconds($TimeoutSeconds)
        $inputString = ""
        $cursorPos   = [Console]::CursorLeft
        
        while ((Get-Date) -lt $endTime) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)  # $true = don't display the key
                
                switch ($key.Key) {
                    'Enter' {
                        Write-Host ""  # Move to next line
                        if ($AllowRefresh -and $inputString -eq "") { 
                            return 'refresh' 
                        }
                        return $inputString.Trim()
                    }
                    'Backspace' {
                        if ($inputString.Length -gt 0) {
                            # Remove last character from string
                            $inputString = $inputString.Substring(0, $inputString.Length - 1)
                            
                            # Move cursor back, write space to clear character, move back again
                            [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
                            [Console]::Write(" ")
                            [Console]::SetCursorPosition([Console]::CursorLeft - 1, [Console]::CursorTop)
                        }
                    }
                    'Escape' {
                        # Clear the entire input
                        if ($inputString.Length -gt 0) {
                            [Console]::SetCursorPosition($cursorPos, [Console]::CursorTop)
                            [Console]::Write(" " * $inputString.Length)
                            [Console]::SetCursorPosition($cursorPos, [Console]::CursorTop)
                            $inputString = ""
                        }
                    }
                    default {
                        # Only add printable characters
                        if ($key.KeyChar -match '[0-9a-zA-Z ]' -or $key.KeyChar -eq '.') {
                            $inputString += $key.KeyChar
                            [Console]::Write($key.KeyChar)
                        }
                    }
                }
            }
            Start-Sleep -Milliseconds 50  # Reduced from 100ms for better responsiveness
        }
        
        if ($inputString.Length -gt 0) {
            Write-Host ""  # Move to next line if there's input
        }
        return $inputString.Trim()
    } catch {
        throw "Error in Read-InputWithTimeout: $_"
    }
}

function Test-CERHostAvailability {
    [CmdletBinding()]
    param(
        [string]$IPAddress,
        [int]$Port               = 987,
        [int]$TimeoutMilliseconds = 1000
    )
    try {
        $tcpClient   = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IPAddress, $Port, $null, $null)
        if ($asyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            $tcpClient.EndConnect($asyncResult)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        if ($tcpClient) { $tcpClient.Close() }
    }
}

function Test-FTPAvailability {
    [CmdletBinding()]
    param(
        [string]$IPAddress,
        [int]$Port               = 21,
        [int]$TimeoutMilliseconds = 1000
    )
    try {
        $tcpClient   = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IPAddress, $Port, $null, $null)
        if ($asyncResult.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            $tcpClient.EndConnect($asyncResult)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        if ($tcpClient) { $tcpClient.Close() }
    }
}

function Get-CERHost {
    [CmdletBinding()]
    param(
        [string]$CerHostPath
    )
    try {
        Write-Host "CERHost.exe not found in script directory. Downloading and installing..." -ForegroundColor Yellow
        Write-Host "This is a one-time download that will be saved to: $CerHostPath" -ForegroundColor Cyan
        
        $downloadUrl = "https://infosys.beckhoff.com/content/1033/cx51x0_hw/Resources/5047075211.zip"
        $tempZipPath = Join-Path $env:TEMP "CERHost.zip"
        $extractPath = Join-Path $env:TEMP "CERHost_Extract"
        $targetDir = Split-Path $CerHostPath -Parent
        
        # Ensure script directory exists (it should, but just in case)
        if (!(Test-Path $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }
        
        # Download the zip file
        Write-Host "Downloading CERHost from Beckhoff..." -ForegroundColor Green
        try {
            # Try using Invoke-WebRequest first (PowerShell 3.0+)
            Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZipPath -UseBasicParsing
        } catch {
            # Fallback to .NET WebClient for older PowerShell versions
            Write-Verbose "Invoke-WebRequest failed, falling back to WebClient"
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($downloadUrl, $tempZipPath)
            $webClient.Dispose()
        }
        
        if (!(Test-Path $tempZipPath)) {
            throw "Failed to download CERHost.zip"
        }
        
        # Extract the zip file
        Write-Host "Extracting CERHost..." -ForegroundColor Green
        
        # Clean up extract directory if it exists
        if (Test-Path $extractPath) {
            Remove-Item $extractPath -Recurse -Force
        }
        
        # Extract using .NET compression (PowerShell 5.0+) or Shell.Application (older versions)
        try {
            # Try PowerShell 5.0+ method first
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($tempZipPath, $extractPath)
        } catch {
            # Fallback to Shell.Application for older PowerShell versions
            Write-Verbose "System.IO.Compression.FileSystem not available, using Shell.Application"
            $shell = New-Object -ComObject Shell.Application
            $zip = $shell.NameSpace($tempZipPath)
            New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
            $destination = $shell.NameSpace($extractPath)
            $destination.CopyHere($zip.Items(), 4)
        }
        
        # Find CERHOST.exe in the extracted files
        $cerHostFiles = Get-ChildItem -Path $extractPath -Filter "CERHOST.exe" -Recurse
        if ($cerHostFiles.Count -eq 0) {
            throw "CERHOST.exe not found in the downloaded archive"
        }
        
        # Copy CERHOST.exe to the target location
        $sourceCerHost = $cerHostFiles[0].FullName
        Copy-Item $sourceCerHost $CerHostPath -Force
        
        # Clean up temporary files
        Remove-Item $tempZipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        
        Write-Host "CERHost.exe successfully downloaded and permanently installed to: $CerHostPath" -ForegroundColor Green
        Write-Host "Future CE device connections will use this local copy." -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to download/extract CERHost: $_"
        
        # Clean up on failure
        Remove-Item $tempZipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        
        return $false
    }
}

function Test-TcXaeMgmtModule {
    [CmdletBinding()]
    param()
    
    try {
        $minimumVersion = [version]'6.2.0'
        Write-Verbose "Checking for TcXaeMgmt module version $minimumVersion or greater"
        
        # Check if version 6.2 or greater is already installed
        $module = Get-Module -ListAvailable -Name TcXaeMgmt |
                  Where-Object { $_.Version -ge $minimumVersion } |
                  Sort-Object Version -Descending |
                  Select-Object -First 1
        
        if (-not $module) {
            Write-Information "TcXaeMgmt version $minimumVersion or greater not found. Installing from PowerShell Gallery..."
            Install-Module -Name TcXaeMgmt -Scope CurrentUser -Force -AcceptLicense -SkipPublisherCheck
            
            # Verify installation
            $module = Get-Module -ListAvailable -Name TcXaeMgmt |
                      Where-Object { $_.Version -ge $minimumVersion } |
                      Sort-Object Version -Descending |
                      Select-Object -First 1
            
            if (-not $module) {
                throw "TcXaeMgmt module version $minimumVersion or greater not found after installation."
            }
        }
        
        # Always load the latest version that meets minimum requirements (6.2.0 or greater)
        Import-Module TcXaeMgmt -RequiredVersion $module.Version -Force
        Write-Verbose "Loaded TcXaeMgmt version $($module.Version)"
        
    } catch {
        throw "Error in Test-TcXaeMgmtModule: $_"
    }
}

function Show-NoTargetsMessage {
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds
    )
    Clear-Host
    Write-Host "No target devices found." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Possible reasons:" -ForegroundColor Cyan
    Write-Host "1. No Beckhoff devices are currently connected or powered on" -ForegroundColor Gray
    Write-Host "2. Network connectivity issues"                              -ForegroundColor Gray
    Write-Host "3. ADS route discovery is not functioning"                 -ForegroundColor Gray
    Write-Host ""
    Write-Host "Automatically retrying in $TimeoutSeconds seconds..."         -ForegroundColor Green
    Write-Host "Press Enter to manually refresh now"                        -ForegroundColor Green
}

function Show-TableAndPrompt {
    [CmdletBinding()]
    param(
        [array]$RemoteRoutes
    )
    try {
        Clear-Host
        
        # Display table headers
        Write-Host ""
        Write-Host ("{0,2}  {1,-20} {2,-15} {3,-20} {4}" -f "#", "Name", "IP Address", "AMS NetID", "OS/Runtime") -ForegroundColor White
        Write-Host ("{0,2}  {1,-20} {2,-15} {3,-20} {4}" -f "--", "--------------------", "---------------", "--------------------", "----------") -ForegroundColor DarkGray
        
        # Build and display the table rows
        $table = for ($i = 0; $i -lt $RemoteRoutes.Count; $i++) {
            $route     = $RemoteRoutes[$i]
            $isUnknown = -not (
                $route.RTSystem -like "Win*"    -or
                $route.RTSystem -like "TcBSD*"  -or
                $route.RTSystem -like "TcRTOS*" -or
                $route.RTSystem -match "Linux"  -or
                $route.RTSystem -match "CE"
            )
            [PSCustomObject]@{
                Number    = $i + 1
                Name      = $route.Name
                IP        = $route.Address
                AMSNetID  = $route.NetId
                OS        = if ($isUnknown) { "$($route.RTSystem) (Unknown)" } else { $route.RTSystem }
                IsUnknown = $isUnknown
            }
        }
        
        foreach ($row in $table) {
            if ($row.IsUnknown) {
                Write-Host ("{0,2}  {1,-20} {2,-15} {3,-20} {4}" -f $row.Number, $row.Name, $row.IP, $row.AMSNetID, $row.OS) -ForegroundColor DarkGray
            } else {
                Write-Host ("{0,2}  {1,-20} {2,-15} {3,-20} {4}" -f $row.Number, $row.Name, $row.IP, $row.AMSNetID, $row.OS)
            }
        }
        
        Write-Host ""
        Write-Host "Select a target by entering its number (or type 'exit' to quit):" -ForegroundColor Cyan
    } catch {
        throw "Error in Show-TableAndPrompt: $_"
    }
}

function Get-DeviceManagerUrl {
    [CmdletBinding()]
    param(
        [psobject]$Route
    )
    switch ($Route.RTSystem) {
        {$_ -like "Win*"}    { return "https://$($Route.Address)/config" }
        {$_ -like "TcBSD*"}  { return "https://$($Route.Address)" }
        {$_ -like "TcRTOS*"} { return "http://$($Route.Address)/config" }
        {$_ -match "Linux"}  { return "https://$($Route.Address)" }
        {$_ -match "CE"}     { return "https://$($Route.Address)/config" }
        default                { throw "Unsupported RTSystem type: $($Route.RTSystem)" }
    }
}

function Show-ConnectionMenu {
    [CmdletBinding()]
    param(
        [psobject]$Route,
        [string]$DeviceManagerUrl,
        [string]$WinSCPPath,
        [string]$CerHostPath,
        [string]$AdminUserName,
        [SecureString]$AdminPassword
    )
    try {
        Write-Host "Connection options for target '$($Route.Name)':" -ForegroundColor Cyan
        switch ($true) {
            ($Route.RTSystem -like "TcBSD*" -or $Route.RTSystem -match "Linux") {
                Write-Host "   1) Open Beckhoff Device Manager webpage ($DeviceManagerUrl)"
                Write-Host "   2) Start SSH session"
                Write-Host "   3) Open WinSCP connection"
                Write-Host "   4) Open both SSH session and WinSCP"
                break
            }
            ($Route.RTSystem -like "TcRTOS*") {
                Write-Host "   1) Open Beckhoff Device Manager webpage ($DeviceManagerUrl)"
                break
            }
            ($Route.RTSystem -like "Win*") {
                Write-Host "   1) Open Beckhoff Device Manager webpage ($DeviceManagerUrl)"
                Write-Host "   2) Start Remote Desktop session"
                break
            }
            ($Route.RTSystem -match "CE") {
                $isCERHostAvailable = Test-CERHostAvailability -IPAddress $Route.Address
                $isFTPAvailable = Test-FTPAvailability -IPAddress $Route.Address
                
                Write-Host "   1) Open Beckhoff Device Manager webpage ($DeviceManagerUrl)"
                
                if ($isCERHostAvailable) {
                    Write-Host "   2) Start CERHost Remote Desktop session" -ForegroundColor Green
                } else {
                    Write-Host "   2) Start CERHost Remote Desktop session" -ForegroundColor Red
                    Write-Host "      Note: CERHost port (987) is not open. Enable CERHost on the host PC." -ForegroundColor Yellow
                }
                
                if ($isFTPAvailable) {
                    Write-Host "   3) Open FTP connection in Windows File Explorer" -ForegroundColor Green
                } else {
                    Write-Host "   3) Open FTP connection in Windows File Explorer" -ForegroundColor Red
                    Write-Host "      Note: FTP port (21) is not open. Enable FTP server on the device." -ForegroundColor Yellow
                }
                break
            }
            default {
                throw "Unsupported RTSystem type: $($Route.RTSystem)"
            }
        }
        return Read-Host "Enter your choice"
    } catch {
        throw "Error in Show-ConnectionMenu: $_"
    }
}

function Invoke-ConnectionChoice {
    [CmdletBinding()]
    param(
        [psobject]$Route,
        [string]$Choice,
        [string]$DeviceManagerUrl,
        [string]$WinSCPPath,
        [string]$CerHostPath,
        [string]$AdminUserName,
        [SecureString]$AdminPassword
    )
    try {
        switch ($Choice) {
            '1' {
                Start-Process $DeviceManagerUrl
            }
            '2' {
                if ($Route.RTSystem -like "Win*") {
                    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword))
                    $cmdkeyCommand = "cmdkey /generic:TERMSRV/$($Route.Address) /user:$AdminUserName /pass:$plainPassword"
                    cmd /c $cmdkeyCommand | Out-Null
                    $rdpFile = Join-Path $env:TEMP ("$($Route.Name -replace '[\\\/:*?"<>|]', '_').rdp")
                    @"
screen mode id:i:2
full address:s:$($Route.Address)
desktopwidth:i:1280
desktopheight:i:720
session bpp:i:32
smart sizing:i:1
"@ | Set-Content $rdpFile -Encoding ASCII
                    Start-Process mstsc.exe $rdpFile
                } elseif ($Route.RTSystem -like "TcBSD*" -or $Route.RTSystem -match "Linux") {
                    $sshCommand = if ($Route.RTSystem -match "Linux") {
                        "ssh -m hmac-sha2-512-etm@openssh.com $AdminUserName@$($Route.Address)"
                    } else {
                        "ssh $AdminUserName@$($Route.Address)"
                    }
                    Start-Process powershell.exe -ArgumentList '-NoExit','-Command',$sshCommand
                } elseif ($Route.RTSystem -match "CE") {
                    # Check if CERHost exists in script directory, if not download it once
                    if (!(Test-Path $CerHostPath)) {
                        Write-Host "CERHost.exe not found in script directory. Downloading for first-time use..." -ForegroundColor Yellow
                        $downloadResult = Get-CERHost -CerHostPath $CerHostPath
                        if (!$downloadResult) {
                            Write-Warning "Failed to download CERHost.exe. Cannot establish CE connection."
                            return
                        }
                    }
                    
                    # Start CERHost using the local copy
                    if (Test-Path $CerHostPath) {
                        Write-Host "Starting CERHost from: $CerHostPath" -ForegroundColor Green
                        Start-Process -FilePath $CerHostPath -ArgumentList $Route.Address
                    } else {
                        Write-Warning "CERHOST.exe still not found at $CerHostPath after download attempt."
                    }
                }
            }
            '3' {
                if ($Route.RTSystem -like "TcBSD*" -or $Route.RTSystem -match "Linux") {
                    try {
                        if (Test-Path $WinSCPPath) {
                            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword))
                            & $WinSCPPath "sftp://${AdminUserName}:$plainPassword@$($Route.Address)/" "/rawsettings" "SftpServer=doas /usr/libexec/sftp-server"
                        } else {
                            & $WinSCPPath "sftp://$($Route.Address)"
                        }
                    } catch {
                        Start-Process "https://winscp.net/eng/download.php"
                    }
                } elseif ($Route.RTSystem -match "CE") {
                    # Open FTP connection in Windows File Explorer for CE devices
                    $ftpUrl = "ftp://$($Route.Address)"
                    Write-Host "Opening FTP connection to: $ftpUrl" -ForegroundColor Green
                    try {
                        # Open Windows File Explorer with FTP URL
                        Start-Process "explorer.exe" -ArgumentList $ftpUrl
                    } catch {
                        Write-Warning "Failed to open FTP connection in File Explorer. Error: $_"
                        Write-Host "You can manually enter this URL in File Explorer: $ftpUrl" -ForegroundColor Cyan
                    }
                }
            }
            '4' {
                if ($Route.RTSystem -like "TcBSD*" -or $Route.RTSystem -match "Linux") {
                    Invoke-ConnectionChoice -Route $Route -Choice '2' -DeviceManagerUrl $DeviceManagerUrl -WinSCPPath $WinSCPPath -CerHostPath $CerHostPath -AdminUserName $AdminUserName -AdminPassword $AdminPassword
                    Invoke-ConnectionChoice -Route $Route -Choice '3' -DeviceManagerUrl $DeviceManagerUrl -WinSCPPath $WinSCPPath -CerHostPath $CerHostPath -AdminUserName $AdminUserName -AdminPassword $AdminPassword
                }
            }
            default { 
                Write-Warning "Invalid choice: $Choice. Please try again."
                return
            }
        }
    } 
    catch {
        throw "Error in Invoke-ConnectionChoice: $_"
    }
}

function Start-ADSDiscovery {
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds,
        [string]$WinSCPPath,
        [string]$CerHostPath,
        [string]$AdminUserName,
        [SecureString]$AdminPassword
    )
    $prevTargetListJSON = ''
    do {
        try {
            $adsRoutes    = Get-AdsRoute -All
            $remoteRoutes = $adsRoutes | Where-Object { -not $_.IsLocal } | Sort-Object Name
            if ($remoteRoutes.Count -eq 0) {
                Show-NoTargetsMessage -TimeoutSeconds $TimeoutSeconds
                $selection = Read-InputWithTimeout -TimeoutSeconds $TimeoutSeconds -AllowRefresh
                if ($selection -eq 'refresh') { continue }
                if ($selection -eq 'exit')    { break }
                continue
            }
            $currentJSON = $remoteRoutes | ConvertTo-Json -Compress -Depth 5
            if ($prevTargetListJSON -ne $currentJSON) {
                Show-TableAndPrompt -RemoteRoutes $remoteRoutes
                $prevTargetListJSON = $currentJSON
            }
            $selection = Read-InputWithTimeout -TimeoutSeconds $TimeoutSeconds
            if ($selection -eq 'exit') { break }
            if (-not $selection) { continue }
            if ($selection -notmatch '^[0-9]+$' -or [int]$selection -lt 1 -or [int]$selection -gt $remoteRoutes.Count) {
                Write-Warning "Invalid selection. Continuing..."
                Start-Sleep -Seconds 1
                # Force screen refresh by clearing the previous JSON
                $prevTargetListJSON = ''
                continue
            }
            $selectedRoute = $remoteRoutes[[int]$selection - 1]
            if (-not (
                $selectedRoute.RTSystem -like "Win*"    -or
                $selectedRoute.RTSystem -like "TcBSD*"  -or
                $selectedRoute.RTSystem -like "TcRTOS*" -or
                $selectedRoute.RTSystem -match "Linux"  -or
                $selectedRoute.RTSystem -match "CE"
            )) {
                Write-Warning "Unsupported device type: $($selectedRoute.RTSystem)"
                Start-Sleep -Seconds 2
                # Force screen refresh by clearing the previous JSON
                $prevTargetListJSON = ''
                continue
            }
            
            Write-Information "Selected target: $($selectedRoute.Name) [$($selectedRoute.Address)] (AMS $($selectedRoute.NetId))"
            $deviceManagerUrl = Get-DeviceManagerUrl -Route $selectedRoute
            $choice           = Show-ConnectionMenu -Route $selectedRoute -DeviceManagerUrl $deviceManagerUrl -WinSCPPath $WinSCPPath -CerHostPath $CerHostPath -AdminUserName $AdminUserName -AdminPassword $AdminPassword
            Invoke-ConnectionChoice -Route $selectedRoute -Choice $choice -DeviceManagerUrl $deviceManagerUrl -WinSCPPath $WinSCPPath -CerHostPath $CerHostPath -AdminUserName $AdminUserName -AdminPassword $AdminPassword
            
            # Automatically return to device list - clear the screen and force refresh
            $prevTargetListJSON = ''
        } catch {
            Write-Error "Error in discovery loop: $_"
        }
    } while ($true)
}

# Entry point
try {
    $ErrorActionPreference = "Stop"
    $ProgressPreference    = "SilentlyContinue"
    
    Test-TcXaeMgmtModule
    Start-ADSDiscovery -TimeoutSeconds $TimeoutSeconds -WinSCPPath $WinSCPPath -CerHostPath $CerHostPath -AdminUserName $AdminUserName -AdminPassword $AdminPassword
} catch {
    Write-Error "Fatal error: $_"
}