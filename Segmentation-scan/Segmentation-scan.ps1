function Get-SegmentationOverview{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    .EXAMPLE
    PS Get-SegmentationReport -xml nmap-scan.xml,nmap-scan2.xml -output out.csv -dns dnsserver.hackme.local
    Hostname            IP          OS                               Ports
    --------            --          --                               -----
    srv000.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     Port 22 Cisco SSH 1.25, Port 3738  , Port 4786
    srv001.hackme.local  10.10.10.2  Cisco 3550 switch (IOS 12.2)     Port 22 Cisco SSH 1.25, Port 4786
    srv002.hackme.local  10.10.10.3  HP ProCurve Secure Router 7102dl Port 22 Cisco SSH 1.25, Port 4786
    #>
    param(
        [string[]]$xml,
        [string]$output = "overview.csv",
        [string]$dns
    )
    begin{
        $table = @()
    }
    process{
        foreach ($x in $xml){
            if(!(Test-Path $x)){
                Write-Output "[-] Could not find $x"
                return
            }
            [xml]$xml=Get-Content $x
            $table += $xml.nmaprun.host | foreach {
                $up = $_ | where {$_.ports.port}
                if($up){
                    $hostname = 'Unknown'
                    if($dns){
                        try{
                            $hostname = ((Resolve-DnsName -Server $dns -Name $up.address.addr -QuickTimeout -ErrorAction SilentlyContinue).NameHost)[0]
                        }catch{}
                    }
                    $OS = 'Unknown'
                    try{    
                        $OS = $up.os.osmatch.name.split(',')[0]
                    }catch{}
                    [pscustomobject]@{
                        Hostname = $hostname
                        IP = $up.address.addr
                        OS = $os
                        Port = foreach($port in $($up.ports.port)){
                            [string]$port.portid
                        }
                    }
                }
            }
        }
    }
    end{
        $table | Select-Object Hostname,IP,@{n='Port';Expression={$_.port -join ", " }},OS | Sort-Object @{e={$_.ip -as [System.Version]}} |Export-Csv -NoTypeInformation -Path $output
    }
}

function Get-SegmentationOverview2{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause
    .EXAMPLE
    PS Get-SegmentationReport -xml nmap-scan.xml,nmap-scan2.xml -output out2.csv -dns dnsserver.hackme.local
    Hostname            IP          OS                               Ports
    --------            --          --                               -----
    srv00.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     Port 22 Cisco SSH 1.25
    srv00.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     Port 3738
    srv00.hackme.local  10.10.10.1  Cisco 3550 switch (IOS 12.2)     Port 4786
    #>
    param(
        [string[]]$xml,

        [string]$output = "overview2.csv",

        [string]$dns
    )
    begin{
        $table = @()
    }
    process{
        foreach ($x in $xml){
            if(!(Test-Path $x)){
                Write-Output "[-] Could not find $x"
                return
            }
            [xml]$xml=Get-Content $x
            $table += $xml.nmaprun.host | foreach {
                $up = $_ | where {$_.ports.port}
                if($up){
                    $hostname = 'Unknown'
                    $OS = 'Unknown'
                    if($dns){
                        try{
                            $hostname = ((Resolve-DnsName -Server $dns -Name $up.address.addr -QuickTimeout -ErrorAction SilentlyContinue).NameHost)[0]
                        }catch{}
                    }
                    try{
                        $OS = $up.os.osmatch.name.split(',')[0]
                    }catch{}
                    foreach($port in $($up.ports.port)){
                        try{
                            $Service = "$($port.service.product) $($port.service.version)"
                        }catch{}
                        if($Service.count -le 1){
                            $Service = 'Unknown'
                        }
                        [pscustomobject]@{
                            Hostname = $hostname
                            IP = $up.address.addr
                            OS = $os
                            Port = $port.portid
                            Service = $Service
                        }
                    }
                }
            }
        }
    }
    end{
        $table | Select-Object Hostname,IP,Port,Service,OS | Sort-Object @{e={$_.ip -as [System.Version]}},@{e={$_.port -as [int]}} | Export-Csv -NoTypeInformation -Path $output
    }
}

function Get-SegmentationReport{
    <#
    .SYNOPSIS
    Author: Cube0x0
    License: BSD 3-Clause

    Parse output from Get-SegmentationOverview and Get-SegmentationOverview2
    .EXAMPLE
    PS Get-SegmentationReport -csv overview.csv,overview2.scv -ReferenceIps ips.txt -ReferencePorts 80,443 -output report.csv
    #>
    param(
        [string[]]$CSV = @('overview.csv','overview2.csv'),

        [string[]]$ReferencePorts = @(22,443,5432,8000,8089),

        [string]$ReferenceIps = 'ref-ips.txt'
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
        $Undocumented_ips = $overviews | where {$_.PSobject.Properties.Name -notcontains 'Service'} | where {$_.ip -notin (Get-Content $ReferenceIps)}
    }
    end{
        $Undocumented_ports | Select-Object Hostname,IP,Port,Service | Sort-Object @{e={$_.ip -as [System.Version]}},@{e={$_.port -as [int]}} | Export-Csv -NoTypeInformation -Path 'Undocumented_ports.csv'
        $Undocumented_ips | Select-Object Hostname,IP,Port | Sort-Object @{e={$_.ip -as [System.Version]}} | Export-Csv -NoTypeInformation -Path 'Undocumented_ips.csv'
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
        [string[]]$xml,

        [string]$output = "ips.txt"
    )
    begin{
        $table = @()
    }
    process{
        foreach ($x in $xml){
            if(!(Test-Path $x)){
                Write-Output "[-] Could not find $x"
                return
            }
            [xml]$xml=Get-Content $x
            $xml.nmaprun.host | foreach {
                $up = $_| where {$_.ports.port}
                if($up){
                    $table += $up.address.addr
                }
            }
        }
    }
    end{
        $table | sort -Unique
        $table | sort -Unique | Set-Content -Encoding Ascii -Path $output
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
        [string[]]$xml,

        [string]$output = "ports.txt"
    )
    begin{
        $table = @()
    }
    process{
        foreach ($x in $xml){
            if(!(Test-Path $x)){
                Write-Output "[-] Could not find $x"
                return
            }
            [xml]$xml=Get-Content $x
            $xml.nmaprun.host | foreach {
                $up = $_| where {$_.ports.port}
                if($up){
                    $table += $up.ports.port.portid
                }
            }
        }
    }
    end{
        $table | sort -Unique
        $table | sort -Unique | Set-Content -Encoding Ascii -Path $output
    }
}