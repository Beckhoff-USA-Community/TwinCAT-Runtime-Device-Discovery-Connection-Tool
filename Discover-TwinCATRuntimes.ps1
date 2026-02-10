<#
.SYNOPSIS
    Discover TwinCAT runtime devices via ADS broadcast and IPv6 discovery, and offer connection options.
.DESCRIPTION
    This script discovers TwinCAT runtime devices on the network using both ADS route discovery and IPv6 neighbor discovery.
    It provides connection options such as SSH, RDP, FTP, and WinSCP based on the device platform.
    The script uses the TcXaeMgmt PowerShell module for ADS discovery and IPv6 multicast ping for network neighbor discovery.
    IPv6 discovery allows finding Beckhoff devices by their MAC address (00-01-05-xx-xx-xx) even before ADS routes are configured.
    The selected network interface for IPv6 discovery is persisted in .ipv6-interface for future use.
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
        Write-Host ("{0,2}  {1,-20} {2,-28} {3,-20} {4}" -f "#", "Name", "IP Address", "AMS NetID", "OS/Runtime") -ForegroundColor White
        Write-Host ("{0,2}  {1,-20} {2,-28} {3,-20} {4}" -f "--", "--------------------", "----------------------------", "--------------------", "----------") -ForegroundColor DarkGray
        
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

            # Display IPv6 address if no IPv4 available
            $ipDisplay = if ($route.Address) {
                $route.Address
            } elseif ($route.IPv6Address) {
                $route.IPv6Address
            } else {
                "N/A"
            }

            # Display NetID or indicate IPv6-only device
            $netIdDisplay = if ($route.NetId) {
                $route.NetId
            } else {
                "(IPv6 only)"
            }

            # Format OS/Runtime - don't duplicate "Unknown" if already in RTSystem
            $osDisplay = if ($isUnknown -and $route.RTSystem -notmatch "Unknown") {
                "$($route.RTSystem) (Unknown)"
            } else {
                $route.RTSystem
            }

            [PSCustomObject]@{
                Number    = $i + 1
                Name      = $route.Name
                IP        = $ipDisplay
                AMSNetID  = $netIdDisplay
                OS        = $osDisplay
                IsUnknown = $isUnknown
            }
        }
        
        foreach ($row in $table) {
            if ($row.IsUnknown) {
                Write-Host ("{0,2}  {1,-20} {2,-28} {3,-20} {4}" -f $row.Number, $row.Name, $row.IP, $row.AMSNetID, $row.OS) -ForegroundColor DarkGray
            } else {
                Write-Host ("{0,2}  {1,-20} {2,-28} {3,-20} {4}" -f $row.Number, $row.Name, $row.IP, $row.AMSNetID, $row.OS)
            }
        }
        
        Write-Host ""
        Write-Host "Select a target by entering its number (or type 'exit' to quit):" -ForegroundColor Cyan
    } catch {
        throw "Error in Show-TableAndPrompt: $_"
    }
}

function Get-ConnectionIPAddress {
    [CmdletBinding()]
    param(
        [psobject]$Route,
        [switch]$ForURL
    )

    if ($Route.Address) {
        return $Route.Address
    } elseif ($Route.IPv6Address) {
        if ($ForURL) {
            return "[$($Route.IPv6Address)]"  # IPv6 addresses in URLs need brackets
        } else {
            return $Route.IPv6Address
        }
    } else {
        throw "No IP address available for device"
    }
}

function Get-DeviceManagerUrl {
    [CmdletBinding()]
    param(
        [psobject]$Route
    )

    # Determine IP address (prefer IPv4, fallback to IPv6)
    $ipAddress = Get-ConnectionIPAddress -Route $Route -ForURL

    switch ($Route.RTSystem) {
        {$_ -like "Win*"}    { return "https://${ipAddress}/config" }
        {$_ -like "TcBSD*"}  { return "https://${ipAddress}" }
        {$_ -like "TcRTOS*"} { return "http://${ipAddress}/config" }
        {$_ -match "Linux"}  { return "https://${ipAddress}" }
        {$_ -match "CE"}     { return "https://${ipAddress}/config" }
        {$_ -match "Unknown"} { return "https://${ipAddress}" }  # Default to HTTPS for unknown
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
                $ipAddress = Get-ConnectionIPAddress -Route $Route
                $isCERHostAvailable = Test-CERHostAvailability -IPAddress $ipAddress
                $isFTPAvailable = Test-FTPAvailability -IPAddress $ipAddress
                
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
            ($Route.RTSystem -match "Unknown") {
                Write-Host "   1) Open Beckhoff Device Manager webpage ($DeviceManagerUrl)"
                Write-Host "   2) Start SSH session (IPv6)"
                Write-Host ""
                Write-Host "   Note: Device discovered via IPv6. Platform type unknown." -ForegroundColor Yellow
                Write-Host "   SSH will attempt connection - credentials required." -ForegroundColor Yellow
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
                    $ipAddress = Get-ConnectionIPAddress -Route $Route
                    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword))
                    $cmdkeyCommand = "cmdkey /generic:TERMSRV/$ipAddress /user:$AdminUserName /pass:$plainPassword"
                    cmd /c $cmdkeyCommand | Out-Null
                    $rdpFile = Join-Path $env:TEMP ("$($Route.Name -replace '[\\\/:*?"<>|]', '_').rdp")
                    @"
screen mode id:i:2
full address:s:$ipAddress
desktopwidth:i:1280
desktopheight:i:720
session bpp:i:32
smart sizing:i:1
"@ | Set-Content $rdpFile -Encoding ASCII
                    Start-Process mstsc.exe $rdpFile
                } elseif ($Route.RTSystem -like "TcBSD*" -or $Route.RTSystem -match "Linux") {
                    $ipAddress = Get-ConnectionIPAddress -Route $Route
                    $sshCommand = if ($Route.RTSystem -match "Linux") {
                        "ssh -m hmac-sha2-512-etm@openssh.com $AdminUserName@$ipAddress"
                    } else {
                        "ssh $AdminUserName@$ipAddress"
                    }
                    Start-Process powershell.exe -ArgumentList '-NoExit','-Command',$sshCommand
                } elseif ($Route.RTSystem -match "Unknown") {
                    # SSH to IPv6-discovered device
                    if ($Route.IPv6Address -and $Route.InterfaceIndex) {
                        # Format: ssh user@ipv6address%interfaceindex
                        $sshTarget = "$($Route.IPv6Address)%$($Route.InterfaceIndex)"
                        $sshCommand = "ssh $AdminUserName@$sshTarget"
                        Write-Host "Connecting via SSH to: $sshTarget" -ForegroundColor Green
                        Start-Process powershell.exe -ArgumentList '-NoExit','-Command',$sshCommand
                    } elseif ($Route.Address) {
                        # Fallback to IPv4 if available
                        $sshCommand = "ssh $AdminUserName@$($Route.Address)"
                        Write-Host "Connecting via SSH to: $($Route.Address)" -ForegroundColor Green
                        Start-Process powershell.exe -ArgumentList '-NoExit','-Command',$sshCommand
                    } else {
                        Write-Warning "No IP address available for SSH connection"
                    }
                } elseif ($Route.RTSystem -match "CE") {
                    $ipAddress = Get-ConnectionIPAddress -Route $Route
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
                        Start-Process -FilePath $CerHostPath -ArgumentList $ipAddress
                    } else {
                        Write-Warning "CERHOST.exe still not found at $CerHostPath after download attempt."
                    }
                }
            }
            '3' {
                if ($Route.RTSystem -like "TcBSD*" -or $Route.RTSystem -match "Linux") {
                    $ipAddress = Get-ConnectionIPAddress -Route $Route
                    try {
                        if (Test-Path $WinSCPPath) {
                            $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword))

                            # Use appropriate SFTP server path based on OS
                            $sftpServer = if ($Route.RTSystem -match "Linux") {
                                "sudo /usr/lib/openssh/sftp-server"
                            } else {
                                "doas /usr/libexec/sftp-server"  # TcBSD
                            }

                            & $WinSCPPath "sftp://${AdminUserName}:$plainPassword@${ipAddress}/" "/rawsettings" "SftpServer=$sftpServer"
                        } else {
                            & $WinSCPPath "sftp://${ipAddress}"
                        }
                    } catch {
                        Start-Process "https://winscp.net/eng/download.php"
                    }
                } elseif ($Route.RTSystem -match "CE") {
                    $ipAddress = Get-ConnectionIPAddress -Route $Route
                    # Open FTP connection in Windows File Explorer for CE devices
                    $ftpUrl = "ftp://${ipAddress}"
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

function Get-StoredNetworkInterface {
    [CmdletBinding()]
    param(
        [string]$ConfigFilePath = "$PSScriptRoot\.ipv6-interface"
    )
    try {
        if (Test-Path $ConfigFilePath) {
            $ifIndexContent = Get-Content $ConfigFilePath -Raw -ErrorAction SilentlyContinue
            $ifIndex = $ifIndexContent.Trim()

            Write-Verbose "Read interface index from file: '$ifIndex'"

            if ($ifIndex -match '^\d+$') {
                $ifIndexInt = [int]$ifIndex
                Write-Verbose "Attempting to load interface with index: $ifIndexInt"

                $adapter = Get-NetAdapter -InterfaceIndex $ifIndexInt -ErrorAction SilentlyContinue
                if ($adapter -and $adapter.Status -eq 'Up') {
                    Write-Verbose "Loaded stored interface: [$($adapter.ifIndex)] $($adapter.Name)"
                    return $adapter
                } else {
                    Write-Verbose "Stored interface no longer available or not up"
                }
            } else {
                Write-Verbose "Invalid interface index format in file: '$ifIndex'"
            }
        } else {
            Write-Verbose "Config file not found: $ConfigFilePath"
        }
        return $null
    } catch {
        Write-Verbose "Error loading stored interface: $_"
        return $null
    }
}

function Select-AndPersistNetworkInterface {
    [CmdletBinding()]
    param(
        [string]$ConfigFilePath = "$PSScriptRoot\.ipv6-interface"
    )
    try {
        Write-Host "`nIPv6 Discovery - Select Network Interface:" -ForegroundColor Cyan
        Write-Host "-------------------------------------------" -ForegroundColor DarkGray

        $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'

        if ($adapters.Count -eq 0) {
            Write-Warning "No active network interfaces found"
            return $null
        }

        $i = 1
        foreach ($adapter in $adapters) {
            $ipv6 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                    Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
                    Select-Object -First 1

            $ipDisplay = if ($ipv6) { $ipv6.IPAddress } else { "No IPv6" }
            Write-Host "$i. [$($adapter.ifIndex)] $($adapter.Name) - $ipDisplay" -ForegroundColor White
            $i++
        }

        Write-Host ""
        Write-Host "Enter interface number (1-$($adapters.Count)) or 'skip' to disable IPv6 discovery: " -ForegroundColor Yellow -NoNewline
        $selection = Read-Host

        if ($selection -eq 'skip') {
            Write-Host "IPv6 discovery disabled" -ForegroundColor Yellow
            return $null
        }

        if ($selection -match '^\d+$' -and [int]$selection -ge 1 -and [int]$selection -le $adapters.Count) {
            $selectedAdapter = $adapters[[int]$selection - 1]

            # Persist the selection (write as string without trailing newline)
            $selectedAdapter.ifIndex.ToString() | Set-Content $ConfigFilePath -NoNewline -Force

            Write-Verbose "Saved interface index $($selectedAdapter.ifIndex) to $ConfigFilePath"
            Write-Host "Selected and saved: [$($selectedAdapter.ifIndex)] $($selectedAdapter.Name)" -ForegroundColor Green
            Write-Host "This interface will be used for future IPv6 discovery" -ForegroundColor Gray
            Write-Host ""

            return $selectedAdapter
        } else {
            Write-Warning "Invalid selection"
            return $null
        }
    } catch {
        Write-Error "Error in Select-AndPersistNetworkInterface: $_"
        return $null
    }
}

function Invoke-IPv6Discovery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$NetworkInterface
    )
    try {
        Write-Verbose "Starting IPv6 discovery on interface [$($NetworkInterface.ifIndex)] $($NetworkInterface.Name)"

        # Ping IPv6 multicast to populate neighbor cache
        $pingResult = ping "ff02::1%$($NetworkInterface.ifIndex)" -n 1 -w 500 2>&1
        Write-Verbose "IPv6 multicast ping completed"

        # Short delay to allow neighbor cache to populate
        Start-Sleep -Milliseconds 500

        # Find Beckhoff devices by MAC address (00-01-05-xx-xx-xx)
        $beckhoffDevices = @(Get-NetNeighbor -LinkLayerAddress "00-01-05*" -AddressFamily IPv6 -ErrorAction SilentlyContinue)

        Write-Verbose "Found $($beckhoffDevices.Count) Beckhoff device(s) via IPv6"

        $results = @()
        foreach ($device in $beckhoffDevices) {
            # Try to find corresponding IPv4 address
            $ipv4Neighbor = Get-NetNeighbor -LinkLayerAddress $device.LinkLayerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue

            $ipv4Address = if ($ipv4Neighbor) { $ipv4Neighbor.IPAddress } else { $null }

            # Extract a device name from MAC address (last 6 digits)
            $macSuffix = $device.LinkLayerAddress -replace '-','' | Select-Object -Last 6
            $deviceName = "Beckhoff-$macSuffix"

            $results += [PSCustomObject]@{
                Name              = $deviceName
                Address           = $ipv4Address
                IPv6Address       = $device.IPAddress
                NetId             = $null
                RTSystem          = "Unknown (IPv6)"
                LinkLayerAddress  = $device.LinkLayerAddress
                DiscoveryMethod   = "IPv6"
                InterfaceIndex    = $device.InterfaceIndex
            }
        }

        return $results
    } catch {
        Write-Error "Error in Invoke-IPv6Discovery: $_"
        return @()
    }
}

function Merge-DiscoveryResults {
    [CmdletBinding()]
    param(
        [array]$AdsRoutes,
        [array]$IPv6Devices
    )
    try {
        $merged = @()
        $ipv4Addresses = @{}

        # Add all ADS routes first
        foreach ($route in $AdsRoutes) {
            $merged += $route
            if ($route.Address) {
                $ipv4Addresses[$route.Address] = $true
            }
        }

        # Add IPv6-discovered devices that don't have a matching IPv4 in ADS routes
        foreach ($device in $IPv6Devices) {
            $alreadyExists = $false

            # Check if this device was already found via ADS (by IPv4 address)
            if ($device.Address -and $ipv4Addresses.ContainsKey($device.Address)) {
                $alreadyExists = $true
                Write-Verbose "IPv6 device $($device.Name) already found via ADS, skipping duplicate"
            }

            if (-not $alreadyExists) {
                $merged += $device
            }
        }

        return $merged
    } catch {
        Write-Error "Error in Merge-DiscoveryResults: $_"
        return $AdsRoutes
    }
}

function Start-ADSDiscovery {
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds,
        [string]$WinSCPPath,
        [string]$CerHostPath,
        [string]$AdminUserName,
        [SecureString]$AdminPassword,
        [object]$IPv6Interface = $null
    )
    $prevTargetListJSON = ''
    $discoveryAttempts = 0
    do {
        try {
            $discoveryAttempts++
            Write-Verbose "Discovery attempt #$discoveryAttempts - Forcing fresh ADS route discovery..."

            $adsRoutes    = Get-AdsRoute -All -Force
            $remoteRoutes = $adsRoutes | Where-Object { -not $_.IsLocal } | Sort-Object Name

            Write-Verbose "ADS Discovery completed: Found $($remoteRoutes.Count) remote devices"

            # Perform IPv6 discovery if interface is configured
            $ipv6Devices = @()
            if ($IPv6Interface) {
                Write-Verbose "Performing IPv6 discovery on interface [$($IPv6Interface.ifIndex)] $($IPv6Interface.Name)"
                $ipv6Devices = Invoke-IPv6Discovery -NetworkInterface $IPv6Interface
                Write-Verbose "IPv6 Discovery completed: Found $($ipv6Devices.Count) devices"
            }

            # Merge ADS and IPv6 results
            $remoteRoutes = Merge-DiscoveryResults -AdsRoutes $remoteRoutes -IPv6Devices $ipv6Devices

            Write-Verbose "Total devices after merge: $($remoteRoutes.Count)"

            if ($remoteRoutes.Count -eq 0) {
                Write-Verbose "No devices found, showing retry message"
                # Clear previous JSON when no devices found to ensure fresh display when devices appear
                $prevTargetListJSON = ''
                Show-NoTargetsMessage -TimeoutSeconds $TimeoutSeconds
                $selection = Read-InputWithTimeout -TimeoutSeconds $TimeoutSeconds -AllowRefresh
                if ($selection -eq 'refresh') {
                    Write-Verbose "Manual refresh requested, clearing cache and retrying..."
                    continue
                }
                if ($selection -eq 'exit')    { break }
                Write-Verbose "Timeout reached, retrying discovery..."
                continue
            }

            $currentJSON = $remoteRoutes | ConvertTo-Json -Compress -Depth 5
            if ($prevTargetListJSON -ne $currentJSON) {
                Write-Verbose "Device list changed, updating display"
                Show-TableAndPrompt -RemoteRoutes $remoteRoutes
                $prevTargetListJSON = $currentJSON
            } else {
                Write-Verbose "Device list unchanged since last check"
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
                $selectedRoute.RTSystem -match "CE"     -or
                $selectedRoute.RTSystem -match "Unknown"
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
            Write-Error "Error in discovery loop (attempt #$discoveryAttempts): $_"
            Write-Verbose "Retrying discovery after error..."
            Start-Sleep -Seconds 2
        }
    } while ($true)
}

# Entry point
try {
    $ErrorActionPreference = "Stop"
    $ProgressPreference    = "SilentlyContinue"

    Test-TcXaeMgmtModule

    # Initialize IPv6 discovery interface
    Write-Verbose "Checking for stored IPv6 interface configuration..."
    $ipv6Interface = Get-StoredNetworkInterface

    if (-not $ipv6Interface) {
        # No stored interface or it's no longer available - prompt for selection
        Write-Verbose "No stored interface found, prompting for selection"
        $ipv6Interface = Select-AndPersistNetworkInterface

        if (-not $ipv6Interface) {
            Write-Host "IPv6 discovery disabled - continuing with ADS discovery only" -ForegroundColor Yellow
            Write-Host ""
        }
    } else {
        Write-Host "Using stored IPv6 interface: [$($ipv6Interface.ifIndex)] $($ipv6Interface.Name)" -ForegroundColor Green
        Write-Host "To change interface, delete the file: $PSScriptRoot\.ipv6-interface" -ForegroundColor Gray
        Write-Host ""
    }

    Start-ADSDiscovery -TimeoutSeconds $TimeoutSeconds -WinSCPPath $WinSCPPath -CerHostPath $CerHostPath -AdminUserName $AdminUserName -AdminPassword $AdminPassword -IPv6Interface $ipv6Interface
} catch {
    Write-Error "Fatal error: $_"
}