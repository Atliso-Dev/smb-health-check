# Pester 5+. The SMB client cmdlets are mocked, so the test machine's SMB settings are never touched:
#   Invoke-Pester ./tests

BeforeAll {
  $script:Script = Join-Path $PSScriptRoot '..\Atliso-SmbHealthCheck.ps1'

  foreach ($c in 'Get-SmbClientConfiguration', 'Set-SmbClientConfiguration', 'Get-SmbConnection') {
    if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { New-Item -Path "function:global:$c" -Value { param($RequireSecuritySignature, $EnableInsecureGuestLogons, [switch]$Force) } | Out-Null }
  }

  function script:Set-Client([bool]$Signing = $true, [bool]$Guest = $false, [object[]]$Connections = @()) {
    $global:AtlisoClient = [pscustomobject]@{ RequireSecuritySignature = $Signing; EnableInsecureGuestLogons = $Guest }
    $global:AtlisoConnections = $Connections
    Mock Get-SmbClientConfiguration { $global:AtlisoClient }
    Mock Get-SmbConnection { $global:AtlisoConnections }
    Mock Set-SmbClientConfiguration { }
  }
  function script:Conn([string]$Server, [bool]$Signed) { [pscustomobject]@{ ServerName = $Server; ShareName = 'share'; Signed = $Signed; Dialect = '3.1.1' } }

  function script:Invoke-Check([string]$Mode = 'Audit') {
    $out = & $script:Script -Mode $Mode | Out-String
    [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $out }
  }
}

Describe 'Atliso-SmbHealthCheck' {

  BeforeEach {
    $env:LOCALAPPDATA = Join-Path $TestDrive 'appdata'   # log and Bridge marker go here
    Remove-Item (Join-Path $env:LOCALAPPDATA 'Atliso') -Recurse -Force -ErrorAction SilentlyContinue
  }

  It 'Audit: 24H2 defaults and only signed connections: exit 0' {
    Set-Client -Connections @((Conn 'fs01' $true))
    $r = Invoke-Check
    $r.Exit | Should -Be 0
    $r.Output | Should -Match 'Signed OK: \\\\fs01\\share'
  }

  It 'Audit: signing relaxed and guest logons on are two problems, exit 1' {
    Set-Client -Signing $false -Guest $true
    $r = Invoke-Check
    $r.Exit | Should -Be 1
    $r.Output | Should -Match 'Audit finished: 2 problem'
  }

  It 'Audit: an unsigned connection names the server that will break' {
    Set-Client -Connections @((Conn 'OLD-NAS01' $false), (Conn 'fs01' $true))
    $r = Invoke-Check
    $r.Exit | Should -Be 1
    $r.Output | Should -Match 'UNSIGNED CONNECTION: \\\\OLD-NAS01\\share'
  }

  It 'Audit never changes client settings' {
    Set-Client -Signing $false -Guest $true -Connections @((Conn 'x' $false))
    Invoke-Check | Out-Null
    Should -Invoke Set-SmbClientConfiguration -Times 0
  }

  It 'Bridge relaxes signing and guest logons and leaves a marker that Audit reports' {
    Set-Client
    (Invoke-Check Bridge).Exit | Should -Be 0
    Should -Invoke Set-SmbClientConfiguration -Times 1 -Exactly -ParameterFilter { $RequireSecuritySignature -eq $false }
    Should -Invoke Set-SmbClientConfiguration -Times 1 -Exactly -ParameterFilter { $EnableInsecureGuestLogons -eq $true }
    Test-Path (Join-Path $env:LOCALAPPDATA 'Atliso\SmbBridge.active') | Should -BeTrue
    (Invoke-Check).Output | Should -Match 'Bridge marker present'
  }

  It 'Restore re-hardens to the 24H2 defaults and removes the marker' {
    Set-Client
    Invoke-Check Bridge | Out-Null
    (Invoke-Check Restore).Exit | Should -Be 0
    Should -Invoke Set-SmbClientConfiguration -ParameterFilter { $RequireSecuritySignature -eq $true }
    Should -Invoke Set-SmbClientConfiguration -ParameterFilter { $EnableInsecureGuestLogons -eq $false }
    Test-Path (Join-Path $env:LOCALAPPDATA 'Atliso\SmbBridge.active') | Should -BeFalse
  }
}
