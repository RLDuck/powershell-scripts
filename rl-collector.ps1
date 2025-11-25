<#
.SYNOPSIS
    A command-line PowerShell collector for forensic artifacts using Eric Zimmerman's tools.
.DESCRIPTION
    This script provides a fully automated, command-line workflow to collect critical forensic evidence from a live Windows system.
    1.  Automatically requests and runs with Administrator privileges.
    2.  Downloads and extracts Eric Zimmerman tools into a 'Tools' directory.
    3.  Runs each tool against system artifacts, showing all progress and output in the console.
    4.  Logs the entire session to a timestamped transcript file in the 'Evidence' directory for a complete audit.
.PARAMETER WorkingDirectory
    Specifies the root folder where the 'Tools' and 'Evidence' directories will be created.
    Defaults to the script's current location.
.PARAMETER ForceCleanup
    A switch that, when specified, will completely remove the 'Tools' directory and all its contents upon script completion.
.EXAMPLE
    .\RLCollector-CLI.ps1
    Runs the entire collection process in the current console window. The script will request elevation if not already an admin.
.EXAMPLE
    .\RLCollector-CLI.ps1 -WorkingDirectory "C:\ForensicImages\Case001" -ForceCleanup
    Runs the collection, stores evidence in 'C:\ForensicImages\Case001\Evidence', and removes the tools directory afterward.
.NOTES
    Author: UnMonsieur
    Version: 7.1
    Requires an Administration Elevation.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Root folder for 'Tools' and 'Evidence' directories.")]
    [string]$WorkingDirectory = $PSScriptRoot,

    [Parameter(Mandatory = $false, HelpMessage = "If specified, deletes the 'Tools' directory upon completion.")]
    [switch]$ForceCleanup
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Attempting to re-launch as Admin..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" -WorkingDirectory `"{1}`"" -f $MyInvocation.MyCommand.Path, $WorkingDirectory)
    exit
}

$art = @"
 ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ 
/_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____/
._. __________ .____         _________          .__   .__                   __                   ._.
| | \______   \|    |        \_   ___ \   ____  |  |  |  |    ____   ____ _/  |_   ____ _______  | |
|_|  |       _/|    |        /    \  \/  /  _ \ |  |  |  |  _/ __ \_/ ___\\   __\ /  _ \\_  __ \ |_|
|-|  |    |   \|    |___     \     \____(  <_> )|  |__|  |__\  ___/\  \___ |  |  (  <_> )|  | \/ |-|
| |  |____|_  /|_______ \     \______  / \____/ |____/|____/ \___  >\___  >|__|   \____/ |__|    | |
|_|         \/         \/            \/                          \/     \/                       |_|
 ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ ______ 
/_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____//_____/

== PowerShell CLI Edition ~ by Konstantine (UnMonsieur)
"@
Write-Host $art -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($WorkingDirectory) -or (-not (Test-Path $WorkingDirectory))) {
    $WorkingDirectory = Get-Location
    Write-Warning "Invalid WorkingDirectory provided. Defaulting to current location: $WorkingDirectory"
}

$script:ToolsDir = Join-Path -Path $WorkingDirectory -ChildPath "Tools"
$script:EvidenceDir = Join-Path -Path $WorkingDirectory -ChildPath "Evidence"

if (-not (Test-Path $script:ToolsDir)) { New-Item -Path $script:ToolsDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $script:EvidenceDir)) { New-Item -Path $script:EvidenceDir -ItemType Directory -Force | Out-Null }

$LogFile = Join-Path -Path $script:EvidenceDir -ChildPath "RLCollector-Log-$(Get-Date -f yyyyMMdd-HHmmss).txt"
Start-Transcript -Path $LogFile
Write-Host "Transcript started. All console output is being logged to: $LogFile" -ForegroundColor Yellow


function Get-ZimmermanTools {
    param($ToolsDir)
    Write-Host "`n[*] Starting tool download and extraction..." -ForegroundColor Green
    
    $toolUrls = @(
        "https://download.ericzimmermanstools.com/net9/EvtxECmd.zip", "https://download.ericzimmermanstools.com/net9/PECmd.zip",
        "https://download.ericzimmermanstools.com/net9/RECmd.zip", "https://download.ericzimmermanstools.com/net9/SBECmd.zip",
        "https://download.ericzimmermanstools.com/net9/SQLECmd.zip", "https://download.ericzimmermanstools.com/net9/SrumECmd.zip",
        "https://download.ericzimmermanstools.com/net9/SumECmd.zip", "https://download.ericzimmermanstools.com/net9/WxTCmd.zip"
    )

    for ($i = 0; $i -lt $toolUrls.Count; $i++) {
        $url = $toolUrls[$i]
        $fileName = [System.IO.Path]::GetFileName($url)
        $zipPath = Join-Path -Path $ToolsDir -ChildPath $fileName
        
        Write-Progress -Activity "Downloading Forensic Tools" -Status "Downloading $fileName..." -PercentComplete (($i / $toolUrls.Count) * 100)

        try {
            Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
            Expand-Archive -Path $zipPath -DestinationPath $ToolsDir -Force
            Remove-Item -Path $zipPath -Force
            Write-Host " [OK] Downloaded and extracted $fileName" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Failed to process $fileName. Error: $($_.Exception.Message)"
            throw "A tool download failed. Cannot continue."
        }
    }
    Write-Progress -Activity "Downloading Forensic Tools" -Completed
    Write-Host "[+] All tools downloaded successfully." -ForegroundColor Green
}

function Invoke-ForensicTool {
    param([string]$Name, [string]$Tool, [string]$ArgumentList)
    Write-Host "`n[*] Executing: $Name" -ForegroundColor Cyan
    
    $toolExecutable = (Get-ChildItem -Path $script:ToolsDir -Recurse -Filter $Tool -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not $toolExecutable) {
        Write-Error "Tool executable '$Tool' not found in '$script:ToolsDir'."
        return
    }

    $toolPath = $toolExecutable.FullName
    $toolDirectory = $toolExecutable.DirectoryName

    $process = Start-Process -FilePath $toolPath -ArgumentList $ArgumentList -WorkingDirectory $toolDirectory -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0) {
        Write-Host "[+] '$Name' completed successfully." -ForegroundColor Green
    } else {
        Write-Warning "'$Name' completed with a non-zero exit code: $($process.ExitCode)."
    }
}

function Collect-SystemArtifacts {
    Write-Host "`n[*] Starting detailed artifact collection..." -ForegroundColor Green
    
    $forensicCommands = @(
        @{ Name = "Prefetch Files"; Tool = "PECmd.exe"; ArgumentList = "-d `"$($env:SystemRoot)\Prefetch`" --csv `"$script:EvidenceDir`"" },
        @{ Name = "User ShellBags"; Tool = "SBECmd.exe"; ArgumentList = "-d `"$($env:USERPROFILE)\AppData\Local\Microsoft\Windows\`" --csv `"$script:EvidenceDir`"" },
        @{ Name = "System ShellBags"; Tool = "SBECmd.exe"; ArgumentList = "-d `"$($env:SystemRoot)\System32\config\systemprofile\AppData\Local\Microsoft\Windows\`" --csv `"$script:EvidenceDir`"" },
        @{ Name = "SRUM Database"; Tool = "SrumECmd.exe"; ArgumentList = "-d `"$($env:SystemRoot)\System32\sru`" --csv `"$script:EvidenceDir`"" },
        @{ Name = "SUM Database"; Tool = "SumECmd.exe"; ArgumentList = "-d `"$($env:SystemRoot)\system32\LogFiles\Sum`" --csv `"$script:EvidenceDir`"" },
        @{ Name = "Registry Hives (Kroll)"; Tool = "RECmd.exe"; ArgumentList = "-d `"$($env:SystemRoot)\system32\config`" --bn BatchExamples\Kroll_Batch.reb --nl false --csv `"$script:EvidenceDir`"" },
        @{ Name = "Event Logs"; Tool = "EvtxECmd.exe"; ArgumentList = "-d `"$($env:SystemRoot)\System32\winevt\Logs`" --csv `"$script:EvidenceDir`" --dedupe" }
    )

    
    $activitiesPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "ConnectedDevicesPlatform"
    Get-ChildItem -Path $activitiesPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $dbFile = Join-Path -Path $_.FullName -ChildPath "ActivitiesCache.db"
        if (Test-Path $dbFile) { Invoke-ForensicTool -Name "ActivitiesCache ($($_.Name))" -Tool "WxTCmd.exe" -ArgumentList "-f `"$dbFile`" --csv `"$script:EvidenceDir`"" }
    }
    
    
    $dbEvidenceDir = Join-Path -Path $script:EvidenceDir -ChildPath "CopiedDatabases"
    if (-not (Test-Path $dbEvidenceDir)) { New-Item $dbEvidenceDir -ItemType Directory | Out-Null }
    @( (Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Notifications\wpndatabase.db"), (Join-Path $env:SystemRoot "System32\config\systemprofile\AppData\Local\Microsoft\Windows\Notifications\wpndatabase.db"), (Join-Path $env:ProgramData "Microsoft\Diagnosis\EventStore.db") ) | ForEach-Object { if (Test-Path $_) { Copy-Item -Path $_ -Destination $dbEvidenceDir -Force } }
    Invoke-ForensicTool -Name "System Databases" -Tool "SQLECmd.exe" -ArgumentList "-d `"$dbEvidenceDir`" --csv `"$script:EvidenceDir`""

    
    foreach ($command in $forensicCommands) {
        try {
            Invoke-ForensicTool @command
        } catch {
            Write-Warning "An error occurred while running '$($command.Name)': $_"
        }
    }
}

function Perform-Cleanup {
    if ($ForceCleanup.IsPresent) {
        if ($PSCmdlet.ShouldProcess($ToolsDir, "Recursively remove the entire Tools directory")) {
            Write-Host "`n[*] Deleting tools directory as requested..." -ForegroundColor Yellow
            Remove-Item -Path $script:ToolsDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[+] Tools directory removed." -ForegroundColor Green
        }
    } else {
        Write-Host "`n[*] Cleanup skipped. Tools are preserved in '$script:ToolsDir'." -ForegroundColor Yellow
    }
}



try {
    Get-ZimmermanTools -ToolsDir $script:ToolsDir
    Collect-SystemArtifacts
    Write-Host "`n[SUCCESS] Script execution completed." -ForegroundColor Green
} catch {
    Write-Error "A critical error stopped the script: $_"
} finally {
    Perform-Cleanup
    Write-Host "`nScript finished. Stopping transcript log."
    Stop-Transcript
}

