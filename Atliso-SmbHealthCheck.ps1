<#
.SYNOPSIS
    Atliso SMB Health Check - audits SMB client posture and live connections
    on Windows 11 24H2+ devices. Finds the servers that will break (or have
    broken) under the 24H2 SMB signing and guest-auth defaults.

.DESCRIPTION
    Three modes, set in the config block below or via -Mode:

    Audit   (default) Report only. Exits 1 if problems found, 0 if clean.
                      Drop into Intune as a detection script as-is.
    Bridge            TEMPORARY compatibility relaxation on this client
                      (allows unsigned SMB + insecure guest logons). Logs
                      what it changed and stamps a marker for later cleanup.
                      Use narrowly. Fix the server instead wherever possible.
    Restore           Reverses Bridge. Re-hardens to 24H2 defaults.

.NOTES
    Run as SYSTEM or admin (reads/writes machine-level SMB config).
    Log: %LOCALAPPDATA%\Atliso\SmbHealthCheck.log  (ProgramData when SYSTEM)
    Author : Atliso (https://atliso.com) - MIT licence.
#>

param(
    [ValidateSet("Audit", "Bridge", "Restore")]
    [string]$Mode = "Audit"
)

# ══════════════ CONFIG ══════════════
# Servers you KNOW can't sign and have accepted the risk for (lowercase).
# Audit still reports them but won't fail the exit code because of them.
$KnownExceptions = @()   # e.g. @("old-nas01", "printbox")
# ═══════════════════════════════════

$IsSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem
$LogDir   = if ($IsSystem) { "$env:ProgramData\Atliso" } else { "$env:LOCALAPPDATA\Atliso" }
$LogFile  = Join-Path $LogDir "SmbHealthCheck.log"
$Marker   = Join-Path $LogDir "SmbBridge.active"
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $line | Add-Content -Path $LogFile
    Write-Output $Message
}

Write-Log "=== SMB Health Check started (mode: $Mode, host: $env:COMPUTERNAME) ==="

$Client = Get-SmbClientConfiguration

switch ($Mode) {

    "Audit" {
        $Problems = 0

        # 1. Client posture vs 24H2 defaults
        if (-not $Client.RequireSecuritySignature) {
            Write-Log "POSTURE: SMB signing NOT required on this client (24H2 default is required). This device has likely been relaxed."
            $Problems++
        } else {
            Write-Log "Posture: SMB signing required - matches 24H2 default."
        }
        if ($Client.EnableInsecureGuestLogons) {
            Write-Log "POSTURE: insecure guest logons ENABLED on this client (24H2 default is disabled)."
            $Problems++
        } else {
            Write-Log "Posture: insecure guest logons disabled - matches 24H2 default."
        }
        if (Test-Path $Marker) {
            Write-Log "POSTURE: Bridge marker present since $((Get-Item $Marker).CreationTime). This device was deliberately relaxed - review it."
        }

        # 2. Live connections
        $Connections = Get-SmbConnection -ErrorAction SilentlyContinue
        if (-not $Connections) {
            Write-Log "No active SMB connections to inspect right now. Posture checks above still stand."
        }
        foreach ($C in $Connections) {
            $srv = $C.ServerName.ToLower()
            if (-not $C.Signed) {
                if ($KnownExceptions -contains $srv) {
                    Write-Log "UNSIGNED (accepted exception): \\$($C.ServerName)\$($C.ShareName)"
                } else {
                    Write-Log "UNSIGNED CONNECTION: \\$($C.ServerName)\$($C.ShareName) (dialect $($C.Dialect)) - this server will break clients running 24H2 defaults. Fix signing on the server."
                    $Problems++
                }
            } else {
                Write-Log "Signed OK: \\$($C.ServerName)\$($C.ShareName) (dialect $($C.Dialect))"
            }
        }

        Write-Log "=== Audit finished: $Problems problem(s) ==="
        if ($Problems -gt 0) { exit 1 } else { exit 0 }
    }

    "Bridge" {
        Write-Log "BRIDGE: applying TEMPORARY client relaxation. Fix the server and run Restore as soon as possible."
        Write-Log "Before: RequireSecuritySignature=$($Client.RequireSecuritySignature) EnableInsecureGuestLogons=$($Client.EnableInsecureGuestLogons)"

        Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force

        "Bridged $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:USERNAME" | Set-Content -Path $Marker
        Write-Log "BRIDGE applied and marker written. This device now accepts unsigned SMB and guest logons."
        exit 0
    }

    "Restore" {
        Write-Log "RESTORE: re-hardening client to 24H2 defaults."
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
        if (Test-Path $Marker) { Remove-Item $Marker -Force }
        Write-Log "RESTORE complete. Signing required, guest logons disabled, marker removed."
        exit 0
    }
}
