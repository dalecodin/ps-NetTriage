# ps-NetTriage 100% Chat-GPT

A one-command **network health check** tool written in PowerShell.  
It runs a quick diagnostic checklist and prints PASS/FAIL results.

## Features
- Detects the primary network adapter
- Checks adapter status, IPv4 address (flags APIPA), default gateway, and DNS servers
- Pings the gateway and a public IP (1.1.1.1)
- Tests DNS resolution (www.microsoft.com)
- Tests TCP reachability on ports 80 and 443
- Displays DHCP server info if available
- Exports results to **JSON** or **CSV** (via `-Export` parameter)
- Optional **Quick Fixes** (`-Fix`) for common issues:
  - Renew DHCP lease
  - Flush DNS cache

## Usage
Run the script in PowerShell:

```powershell
# Basic run
.\src\NetTriage.ps1

# Export results to JSON
.\src\NetTriage.ps1 -Export results.json

# Export to CSV
.\src\NetTriage.ps1 -Export results.csv

# Run with auto-fix prompts
.\src\NetTriage.ps1 -Fix
