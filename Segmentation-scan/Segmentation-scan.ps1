function Get-SegmentationReport{
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
        [string]$output = "results.csv",
        [string]$dns = '10.48.48.2'
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
                    $hostname = 'Unknowned'
                    try{
                        $hostname = ((Resolve-DnsName -Server $dns -Name $up.address.addr).NameHost)
                    }catch{}
                    $OS = 'Unknowned'
                    try{
                        $OS = $up.os.osmatch.name.split(',')[0]
                    }catch{}
                    [pscustomobject]@{
                        Hostname = $hostname
                        IP = $up.address.addr
                        OS = $os
                        Ports = foreach($port in $($up.ports.port)){
                            $("Port $($port.portid) $($port.service.product) $($port.service.version)")
                        }
                    }
                }
            }
        }
    }
    end{
        $table | Select-Object Hostname,IP,OS,@{n='Ports';Expression={$_.ports -join ", " }} | Export-Csv -NoTypeInformation -Path $output
    }
}

function Get-SegmentationReport2{
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

        [string]$output = "results2.csv",

        [string]$dns = '10.48.48.2'
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
                    $hostname = 'Unknowned'
                    try{
                        $hostname = ((Resolve-DnsName -Server $dns -Name $up.address.addr).NameHost)
                    }catch{}
                    $OS = 'Unknowned'
                    try{
                        $OS = $up.os.osmatch.name.split(',')[0]
                    }catch{}
                    foreach($port in $($up.ports.port)){
                        [pscustomobject]@{
                            Hostname = $hostname
                            IP = $up.address.addr
                            OS = $os
                            Port = $("$($port.portid) $($port.service.product) $($port.service.version)")
                        }
                    }
                }
            }
        }
    }
    end{
        $table | Select-Object Hostname,IP,OS,Port | Export-Csv -NoTypeInformation -Path $output
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