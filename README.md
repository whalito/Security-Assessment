Scripts written to aid automated scanning during whitebox security/vuln assessments

# Poc's
### Invoke-WinEnum.ps1
	Invoke-WinEnum		-  Check Windows host security
* General System Information
* Users in Administrators, RDP, DCOM, PSRemote group
* Firewall, AntiVirus, and Spyware Product for Workstations
* Windows Defender Configuration for Servers
* Autologon Credentials
* Cached GPP Password
* Unattended Install Files
* Unquoted Services Paths
* AlwaysInstallElevated
* UAC Configuration 
* ACL on Non-Default SMB Shares
* ACL on Service Binaries and Directories
* ACL on Scheduled Tasks Binaries and Directories
* ACL on AutoRuns Binaries and Directories for System and Local Administrators
* ACL on Directories located in System and Local Administrators PATHS Variable
* Active Listenings Ports
* Software Credentials in Registry
* Installed Software
* CVE on Installed Software (vulmap)
* WSUS HTTP Config
* Non-standard Services
* Non-standard Processes
* Non-standard scheduled tasks
* Print Spool and Wpad Status
* PowerShell Logging Configuration
* DPAPI Blobs & Masterkeys
* LAPS Configuration
* Lsass Protection
* Sensitive Information in Logs
* SMBv1
* PowerShell v2
* .Net Versions
* Installed Security Patches
* Best Practices Analyzer
* IIS (encrypted web.config strings, encrypted application pools and virtual directory passwords)
* MSSQL (Links, Users, Default and Weak Passwords, Databases, ACL on .mdf, Vulnerable configurations...)

(ACL's for System, Local Administrators, and TrustedInstaller is being ignored)
### SecurityAssessment.ps1
	Invoke-LinuxSSH		  -  Run Bash scripts on multiple hosts simultaneously with Posh-SSH
	Invoke-WindowsWMI	  -  Run PowerShell on multiple hosts simultaneously with WMI
	Invoke-WindowsPS	  -  Run PowerShell on multiple hosts simultaneously with PSRemote
	Invoke-WindowsSMB	  -  Run PowerShell on multiple hosts with WMI and output over SMB
	Invoke-Grouper2		  -  GPO Audit
	Invoke-PingCastle	  -  Runs multiple pingcastle modules
	Invoke-DomainEnum	  -  Runs multiple checks on the domain
	Get-BlueKeepStatus	  -  PingCastle Bluekeep script
	Get-SpoolStatus		  -  PingCastle Print Spooler status script
	Get-RemoteCertificates	  -  Download all CA and Root Certificates from a remote host using OpenRemoteBaseKey
	Get-DomainCertificates	  -  Download all published CA, Root and CRL certificates
	Get-DomainExchangeVersion -  Get exchange version from ADSI and check if vuln to privexchange
	Get-DefaultPassword	  -  Search for default passwords for a specific vendor/product
	Get-WeakPasswords	  -  Find weak passwords from secretsdump output & hashcat potfile and imports it to bloodhound
	New-SYSVOLZip		  -  Zip Sysvol for Grouper2
	ConvertFrom-CisHtml	  -  Convert CIS html report to docx
### bloodhoundanalytics.py
	Gather Active Directory statistics from BloodHound data
# Software

https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10

https://github.com/CISOfy/lynis

https://github.com/DenizParlak/Zeus

https://www.pingcastle.com/download/

https://github.com/BloodHoundAD/BloodHound/

https://github.com/dev-sec/windows-baseline

https://github.com/MichaelGrafnetter/DSInternals

# Nessus Audit Files
https://github.com/nsacyber/Windows-Secure-Host-Baseline/tree/master/Windows/Compliance

https://github.com/nsacyber/Windows-Secure-Host-Baseline/tree/master/Windows%20Firewall/Compliance

# Acknowledgments
Thanks to

Harmj0y

lkys37en

A-mIn3
