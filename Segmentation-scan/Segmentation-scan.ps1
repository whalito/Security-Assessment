function Get-AddressOverview{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    .EXAMPLE
    PS Get-AddressOverview -xml nmap-scan.xml,nmap-scan2.xml -output out.csv -dns dnsserver.hackme.local
    Hostname            IP          OS                               Ports
    --------            --          --                               -----
    srv000.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     22, 3738, 4786
    srv001.hackme.local  10.10.10.2  Cisco 3550 switch (IOS 12.2)     22, 4786
    srv002.hackme.local  10.10.10.3  HP ProCurve Secure Router 7102dl 22, 4786
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$xml,

        [Parameter(Mandatory=$true)]
        [string]$output,

        [string]$dns
    )
    begin{
        $table = New-Object System.Collections.ArrayList
    }
    process{
        foreach ($x in $xml){
            if(Test-Path $x){
                try{
                    [xml]$xml=Get-Content $x
                }catch{
                    Write-Output "[-] Failed to open $x"
                    return
                }
                $xml.nmaprun.host | foreach {
                    $ports = New-Object System.Collections.ArrayList
                    $up = $_ | where {$_.ports.port.state.state -contains 'open'}
                    if($up){
                        $hostname = 'Unknown'
                        $OS = 'Unknown'
                        if($dns){
                            try{
                                $hostname = ((Resolve-DnsName -Server $dns -Name $up.address.addr -QuickTimeout -ErrorAction SilentlyContinue).NameHost)[0]
                            }catch{
                                Write-Verbose  "no Hostname found for $($up.address.addr)"
                            }
                        }
                        try{    
                            $OS = $up.os.osmatch.name.split(',')[0]
                        }catch{
                            Write-Verbose  "no OS found for $($up.address.addr)"
                        }
                        foreach($port in $up.ports.port){
                            if($port.state.state -contains 'open'){
                                $ports.add([string]$port.portid)
                            }
                        }
                        $obj=[pscustomobject]@{
                            Hostname = $hostname
                            IP = $up.address.addr
                            OS = $os
                            Port = $ports
                        }
                        $table.add($obj) | Out-Null
                    }
                }
            }else{
                Write-Output "[-] Could not find $x"
            }
        }
    }
    end{
        $table |Select-Object Hostname,IP,@{n='Port';Expression={$_.port -join ", " }},OS | Sort-Object @{e={$_.ip -as [System.Version]}} |Export-Csv -NoTypeInformation -Path $output
    }
}
function Get-ServiceOverview{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    .EXAMPLE
    PS Get-ServiceOverview -xml nmap-scan.xml,nmap-scan2.xml -output out2.csv -dns dnsserver.hackme.local
    Hostname            IP          OS                               Ports
    --------            --          --                               -----
    srv00.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     Port 22 Cisco SSH 1.25
    srv00.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     Port 3738
    srv00.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     Port 4786
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$xml,

        [Parameter(Mandatory=$true)]
        [string]$output,

        [string]$dns
    )
    begin{
        $table = New-Object System.Collections.ArrayList
    }
    process{
        foreach ($x in $xml){
            if(Test-Path $x){
                try{
                    [xml]$xml=Get-Content $x
                }catch{
                    Write-Output "[-] Failed to open $x"
                    return
                }
                $xml.nmaprun.host | foreach {
                    $up = $_ | where {$_.ports.port.state.state -contains 'open'}
                    if($up){
                        $hostname = 'Unknown'
                        $OS = 'Unknown'
                        if($dns){
                            try{
                                $hostname = ((Resolve-DnsName -Server $dns -Name $up.address.addr -QuickTimeout -ErrorAction SilentlyContinue).NameHost)[0]
                            }catch{
                                Write-Verbose "no Hostname found for $($up.address.addr)"
                            }
                        }
                        try{
                            $OS = $up.os.osmatch.name.split(',')[0]
                        }catch{
                            Write-Verbose  "no OS found for $($up.address.addr)"
                        }
                        foreach($port in $up.ports.port){
                            if($port.state.state -contains 'open'){
                                if($port.service.product){
                                    $Service = -join($port.service.product,' ',$port.service.version)
                                }else{
                                    $Service = 'Unknown'
                                }
                                $obj = [pscustomobject]@{
                                    Hostname = $hostname
                                    IP = $up.address.addr
                                    OS = $os
                                    Port = $port.portid
                                    Service = $Service
                                }
                                $table.add($obj) | Out-Null
                            }
                        }
                    }
                }
            }else{
                Write-Output "[-] Could not find $x"
            }
        }
    }
    end{
        $table | Select-Object Hostname,IP,Port,Service,OS | Sort-Object @{e={$_.ip -as [System.Version]}},@{e={$_.port -as [int]}} | Export-Csv -NoTypeInformation -Path $output
    }
}
function Get-UndocumentedAddresses{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Parse output from Get-AddressOverview
    .EXAMPLE
    PS Get-UndocumentedAddresses -csv overview.csv,overview2.scv -ReferenceIps ips.txt -ReferencePorts 80,443 -output report.csv
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$CSV,

        [ValidateScript({Test-Path -Path $_ })]
        [Parameter(Mandatory=$true)]
        [array]$ReferenceAddresses,

        [Parameter(Mandatory=$true)]
        [string]$output
    )
    begin{
        try{
            $overviews = Import-Csv $CSV -ErrorAction Stop
        }catch{
            Write-Output '[-]Could not import csv'
            return
        }
        try{
            [array]$ips = Get-Content $ReferenceAddresses -ErrorAction stop
        }catch{
            Write-Output "[-]Could not import $ReferenceAddresses"
            return
        }
    }
    process{
        $Undocumented_ips = $overviews | where {$_.PSobject.Properties.Name -notcontains 'Service'} | where {$_.ip -notin $ips}
    }
    end{
        $Undocumented_ips | Select-Object Hostname,IP,Port | Sort-Object @{e={$_.ip -as [System.Version]}} | Export-Csv -NoTypeInformation -Path $output
    }
}
function Get-UndocumentedServices{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Parse output from Get-ServiceOverview
    .EXAMPLE
    PS Get-UndocumentedServices -csv overview.csv,overview2.scv -ReferenceIps ips.txt -ReferencePorts 80,443 -output report.csv
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$CSV,
        
        [Parameter(Mandatory=$true)]
        [array]$ReferencePorts,

        [Parameter(Mandatory=$true)]
        [string]$output

    )
    begin{
        try{
            $overviews = Import-Csv $CSV -ErrorAction Stop
        }catch{
            Write-Output '[-]Could not import csv'
            return
        }
    }
    process{
        $Undocumented_ports = $overviews | where {$_.PSobject.Properties.Name -contains 'Service'} | where {$_.port -notin $ReferencePorts}
    }
    end{
        $Undocumented_ports | Select-Object Hostname,IP,Port,Service | Sort-Object @{e={$_.ip -as [System.Version]}},@{e={$_.port -as [int]}} | Export-Csv -NoTypeInformation -Path $output
    }
}
function Get-NmapIP{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    .EXAMPLE
    PS > Get-NmapIP -xml .\nmap-discovery.xml,.\nmap-discovery2.xml
    10.10.10.19
    10.10.10.47
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$xml,

        [string]$output
    )
    begin{
        $table = New-Object System.Collections.ArrayList
    }
    process{
        foreach ($x in $xml){
            if(Test-Path $x){
                try{
                    [xml]$xml=Get-Content $x
                }catch{
                    return
                }
                $xml.nmaprun.host | foreach {
                    $up = $_| where {$_.ports.port.state.state -contains 'open'}
                    if($up){
                        $table.add($up.address.addr) | Out-Null
                    }
                }
            }else{
                Write-Output "[-] Could not find $x"
            }
        }
    }
    end{
        $table | Sort-Object @{e={$_ -as [System.Version]}} -Unique
        if($output){
            $table | Sort-Object @{e={$_ -as [System.Version]}} -Unique | Set-Content -Encoding Ascii -Path $output
        }
    }
}
function Get-NmapPort{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    .EXAMPLE
    PS > Get-NmapPort -xml .\nmap-fullscan.xml,.\nmap-fullscan2.xml 
    22
    80
    443
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$xml,

        [string]$output
    )
    begin{
        $table = New-Object System.Collections.ArrayList
    }
    process{
        foreach ($x in $xml){
            if(Test-Path $x){
                try{
                    [xml]$xml=Get-Content $x
                }catch{
                    return
                }
                $xml.nmaprun.host | foreach{
                    $_.ports.port | foreach{
                        if($_.state.state -contains 'open'){
                            $table.add($_.portid) | Out-Null
                        }
                    }
                }
            }else{
                Write-Output "[-] Could not find $x"
            }
        }
    }
    end{
        $table | Sort-Object -Unique
        if($output){
            $table | Sort-Object -Unique | Set-Content -Encoding Ascii -Path $output
        }
    }
}