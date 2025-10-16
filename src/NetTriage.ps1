[CmdletBinding()]
param(
  [switch]$Fix,
  [string]$Export
)


function New-Result {
  param([string]$Name,[string]$Status,[string]$Details)
  [pscustomobject]@{ Check = $Name; Result = $Status; Details = $Details }
}

function Test-Admin {
  $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
  $wp = New-Object Security.Principal.WindowsPrincipal($wi)
  return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PrimaryNet {
  $cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
  if (-not $cfg) {
    $up = Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq "Up" } | Select-Object -First 1
    if ($up) { return $up }
  }
  return $cfg
}

function Get-IPv4AddressText {
  param($ipconfig)
  $ipPreferred = $ipconfig.IPv4Address | Where-Object { $_.AddressState -eq 'Preferred' } | Select-Object -First 1
  if ($ipPreferred) { return $ipPreferred.IPAddress }
  $ipFirst = $ipconfig.IPv4Address | Select-Object -First 1
  if ($ipFirst) { return $ipFirst.IPAddress }
  return $null
}


function Invoke-NetTriage {
  $results = New-Object System.Collections.Generic.List[object]

  $primary = Get-PrimaryNet
  if (-not $primary) {
    $results.Add((New-Result "Detect primary adapter" "FAIL" "No active adapter found."))
    return ,$results
  }

  $adapter = $primary.NetAdapter
  $ipText  = Get-IPv4AddressText $primary
  $gwText  = $primary.IPv4DefaultGateway.NextHop
  $dnsList = ($primary.DNSServer.ServerAddresses -join ", ")

  # Adapter status
  if ($adapter.Status -eq "Up") {
    $results.Add((New-Result "Adapter status" "PASS" "$($adapter.Name) is Up"))
  } else {
    $results.Add((New-Result "Adapter status" "FAIL" "$($adapter.Name) is $($adapter.Status)"))
  }

  # IPv4 sanity / APIPA
  if ($ipText) {
    if ($ipText -like "169.254.*") {
      $results.Add((New-Result "IPv4 address" "FAIL" "APIPA $ipText (no DHCP lease)"))
    } else {
      $results.Add((New-Result "IPv4 address" "PASS" $ipText))
    }
  } else {
    $results.Add((New-Result "IPv4 address" "FAIL" "No IPv4 assigned"))
  }

  # Default gateway present
  if ($gwText) {
    $results.Add((New-Result "Default gateway" "PASS" $gwText))
  } else {
    $results.Add((New-Result "Default gateway" "FAIL" "No default gateway"))
  }

  # DNS servers present
  if ($dnsList) {
    $results.Add((New-Result "DNS servers" "PASS" $dnsList))
  } else {
    $results.Add((New-Result "DNS servers" "FAIL" "No DNS servers configured"))
  }

  # Ping gateway
  if ($gwText) {
    try {
      $ok = Test-Connection -ComputerName $gwText -Count 2 -Quiet -ErrorAction Stop
      if ($ok) {
        $results.Add((New-Result "Ping gateway" "PASS" "Reachable"))
      } else {
        $results.Add((New-Result "Ping gateway" "FAIL" "No reply"))
      }
    } catch {
      $results.Add((New-Result "Ping gateway" "FAIL" $_.Exception.Message))
    }
  } else {
    $results.Add((New-Result "Ping gateway" "SKIP" "No gateway"))
  }

  # DNS resolve
  try {
    $r = Resolve-DnsName -Name "www.microsoft.com" -Type A -ErrorAction Stop | Select-Object -First 1
    $results.Add((New-Result "DNS resolve" "PASS" ("www.microsoft.com -> " + $r.IPAddress)))
  } catch {
    $results.Add((New-Result "DNS resolve" "FAIL" $_.Exception.Message))
  }

  # Ping public IP
  try {
    $okPub = Test-Connection -ComputerName "1.1.1.1" -Count 2 -Quiet -ErrorAction Stop
    if ($okPub) {
      $results.Add((New-Result "Ping public IP" "PASS" "1.1.1.1 reachable"))
    } else {
      $results.Add((New-Result "Ping public IP" "FAIL" "No reply"))
    }
  } catch {
    $results.Add((New-Result "Ping public IP" "FAIL" $_.Exception.Message))
  }

  # HTTP/HTTPS reachability
  foreach ($port in 80,443) {
    try {
      $tnc = Test-NetConnection -ComputerName "www.microsoft.com" -Port $port -WarningAction SilentlyContinue
      if ($tnc.TcpTestSucceeded) {
        $results.Add((New-Result ("TCP " + $port) "PASS" ("www.microsoft.com:" + $port)))
      } else {
        $results.Add((New-Result ("TCP " + $port) "FAIL" ("www.microsoft.com:" + $port)))
      }
    } catch {
      $results.Add((New-Result ("TCP " + $port) "FAIL" $_.Exception.Message))
    }
  }

  # DHCP info (best-effort; this property may not exist on all systems)
  try {
    if ($primary.DhcpServer) {
      $results.Add((New-Result "DHCP server" "INFO" ("DHCP: " + $primary.DhcpServer)))
    } else {
      $results.Add((New-Result "DHCP server" "INFO" "Static or unknown"))
    }
  } catch {
    $results.Add((New-Result "DHCP server" "INFO" "Unavailable"))
  }

  return ,$results
}

function Invoke-QuickFix {
  param(
    [Parameter(Mandatory=$true)][Microsoft.Management.Infrastructure.CimInstance]$PrimaryConfig
  )

  Write-Host ""
  Write-Host "Quick Fixes (safe & reversible)" -ForegroundColor Cyan

  $isAdmin = Test-Admin
  if (-not $isAdmin) {
    Write-Warning "Some fixes need an elevated PowerShell (Run as Administrator)."
  }

  Write-Host "[1] Renew DHCP lease (ipconfig /release & /renew)"
  Write-Host "[2] Flush DNS cache (ipconfig /flushdns) (Admin)"
  Write-Host "[Q] Quit"

  while ($true) {
    $sel = Read-Host "Select an option"
    switch ($sel.ToUpper()) {
      "1" {
        Write-Host "Releasing and renewing IP..."
        ipconfig /release | Out-Null
        Start-Sleep -Seconds 1
        ipconfig /renew  | Out-Null
        Write-Host "Done." -ForegroundColor Green
      }
      "2" {
        if (-not $isAdmin) {
          Write-Warning "Open PowerShell as Administrator to flush DNS."
        } else {
          Write-Host "Flushing DNS cache..."
          ipconfig /flushdns | Out-Null
          Write-Host "Done." -ForegroundColor Green
        }
      }
      "Q" { break }
      Default { Write-Host "Invalid selection." -ForegroundColor Yellow }
    }
  }
}


$results = Invoke-NetTriage

# Print nice table
$results | Format-Table -AutoSize

# Export if requested
if ($Export) {
  $ext = [IO.Path]::GetExtension($Export).ToLower()
  switch ($ext) {
    ".json" { $results | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $Export }
    ".csv"  { $results | Export-Csv -NoTypeInformation -Encoding UTF8 $Export }
    default { $results | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $Export }
  }
  Write-Host "`nSaved results to $Export" -ForegroundColor Green
}

# Offer fixes if something failed
if ($results.Result -contains "FAIL" -and $Fix) {
  $primary = Get-PrimaryNet
  if ($primary) { Invoke-QuickFix -PrimaryConfig $primary }
}
