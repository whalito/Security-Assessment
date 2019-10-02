function Invoke-SniperCore{
    <#
        .TODO
        Add more recon
        Optimize nmap

        .SYNOPSIS
        Tested on Kali Linux with PowerShell Core V6.2
        SniperCore File: Invoke-SniperCore.ps1
        Author: Cube0x0
        License: BSD 3-Clause

        .DESCRIPTION
        Inspired by Sn1per
        https://github.com/1N3/Sn1per

        .PARAMETER ComputerList
        List of computernames that should be scanned, use FQDN, IP, ranges or CIDR
        Each entry must be separated by one or more spaces, tabs, or newlines.
        svr01.hackme.local
        192.168.3.10
        192.168.4.0/24
        192.168.5.1-255

        .PARAMETER NMapXML
        Already have a nmap scan you want to sniper? Give it the xml format and
        it will skip the first nmap scan and go straight to SearchSploit and ScriptEngine

        .PARAMETER Output
        Output folder for reports
        Needs to be a empty or a non-existing folder

        .PARAMETER MetaSploit
        Enable MetaSploit modules

        .PARAMETER BurpSuite
        Enable Burp scanning
        
        You must have Burpsuite Professional 2.x running on the same host with the following "User Options" > "Misc" set.
        *REST API service enabled on port localhost:1337/tcp
        *Allow access without API key enabled

        .PARAMETER Hydra
        Enable hydra bruteforcing

        .PARAMETER Misc
        Enable Misc tools

        .PARAMETER Web
        Enable Web scanning tools

        .PARAMETER All
        Enable all scanning options

        .EXAMPLE
        Invoke-SniperCore -ComputerList Computers.txt -Misc
        Invoke-SniperCore -ComputerList Computers.txt -BurpSuite -Web
        Invoke-SniperCore -NMapXML nmap-overall.xml -All
    #>
    param(
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_})]
        [string]$ComputerList,
        
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_})]
        [string]$ExcludeComputerList,
        
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path -Path $_})]
        [string]$NmapXML,
        
        [ValidateNotNullOrEmpty()]
        [string]$Output = "$(Get-Location)/output",

        [string]$HydraThreads,

        [switch]$MetaSploit,

        [switch]$BurpSuite,

        [switch]$Hydra,

        [switch]$Misc,

        [switch]$Web,

        [switch]$All,

        [switch]$Tcp,

        [switch]$Udp
    )
    begin{
        if(!$tcp -and !$udp){
            write-output "[*] No TCP/UDP switch was used, doing TCP scan"
            $tcp = $true
        }
        if($HydraThreads){
            $threads = $HydraThreads
        }else{
            $threads = '4'
        }
        if(-not(Test-Path $output)){
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output | Out-Null
        }else{
            $IsNotEmpty=[bool](Get-ChildItem $output\*)
        }
        if($IsNotEmpty){
            throw "[-] $output is not empty"
        }
        if($NmapXML){
            Write-Output "[*] NMap Scan Disabled"
            if(-not((Get-ChildItem $NmapXML).Extension -match '.xml')){
                throw "[-] $NmapXML does not have .xml extension"
            }
            $nmap = $NmapXML
        }
        #Check dependencies
        @(
            'PowerHTML'
            'PoshRSJob'
        ) | ForEach-Object {
            if(-not(Get-Module $_ -ListAvailable)){
                Write-Output "[-] Missing Powershell Modul: $_"
                $missing = $true
            }
        }
        @{
            'Database.csv' = 'https://github.com/cube0x0/Security-Assessment/tree/master/Invoke-SniperCore'
            '/usr/share/nmap/scripts/vulners.nse' = 'https://github.com/vulnersCom/nmap-vulners'
        }.GetEnumerator() | ForEach-Object {
            if(-not(test-path $_.Key)){
                Write-Output "[-] Missing file $($_.key). $($_.value)"
                $missing = $true
            }
        }
        @{
            'burpsuite' = 'https://portswigger.net/burp'
            'ssh-audit' = 'https://github.com/arthepsy/ssh-audit'
            'nikto' = 'https://github.com/sullo/nikto'
            'nmap' = 'https://github.com/nmap/nmap'
            'wafw00f' = 'https://github.com/EnableSecurity/wafw00f'
            'cutycapt' = 'https://github.com/hoehrmann/CutyCapt'
            'smbclient.py' = 'https://github.com/SecureAuthCorp/impacket'
            'sslscan' = 'https://github.com/rbsec/sslscan'
            'ike-scan' = 'https://github.com/royhills/ike-scan'
            'msfconsole' = 'https://github.com/rapid7/metasploit-framework'
            'searchsploit' =  'https://github.com/offensive-security/exploitdb'
            'wpscan' = 'https://github.com/wpscanteam/wpscan'
            'svmap' = 'https://github.com/EnableSecurity/sipvicious'
            'svwar' = 'https://github.com/EnableSecurity/sipvicious'
            'showmount' = 'sudo apt-install nfs-common'
        }.GetEnumerator() | ForEach-Object {
            if(-not(get-command $_.Key -ErrorAction SilentlyContinue)){
                Write-Output "[-] Missing binary $($_.key) in PATH. $($_.value)"
                $missing = $true
            }
        }
        if($missing){
            throw "[-] Missing dependencies"
        }
        if($All){
            $MetaSploit = $true
            $BurpSuite = $true
            $Hydra = $true
            $Misc = $true
            $Web = $true
        }
        if($MetaSploit){
            Write-Output "[*] Starting postgresql"
            service postgresql start
        }    
    }
    process{
        if(-not($NmapXML)){
            #https://www.poftut.com/nmap-timing-performance/
            #https://nmap.org/book/man-performance.html
            $HostCount = (cat $ComputerList | Measure-Object -Line).lines
            $min_hostgroup = $HostCount / 4
            $min_paralell = $HostCount / 8
            if($min_paralell -lt 10){
                $min_paralell = 10
            }
            if($min_hostgroup -lt 20){
                $min_hostgroup = 20
            }
            $top1000='2-3,7,9,13,17,19-23,37-38,42,49,53,67-69,80,88,111-113,120,123,135-139,158,161-162,177,192,199,207,217,363,389,402,407,427,434,443,445,464,497,500,502,512-515,517-518,520,539,559,593,623,626,631,639,643,657,664,682-689,764,767,772-776,780-782,786,789,800,814,826,829,838,902-903,944,959,965,983,989-990,996-1001,1007-1008,1012-1014,1019-1051,1053-1060,1064-1070,1072,1080-1081,1087-1088,1090,1100-1101,1105,1124,1200,1214,1234,1346,1419,1433-1434,1455,1457,1484-1485,1524,1645-1646,1701,1718-1719,1761,1782,1804,1812-1813,1885-1886,1900-1901,1993,2000,2002,2048-2049,2051,2148,2160-2161,2222-2223,2343,2345,2362,2967,3052,3130,3283,3296,3343,3389,3401,3456-3457,3659,3664,3702-3703,4000,4008,4045,4444,4500,4666,4672,5000-5003,5010,5050,5060,5093,5351,5353,5355,5500,5555,5632,6000-6002,6004,6050,6346-6347,6970-6971,7000,7938,8000-8001,8010,8181,8193,8900,9000-9001,9020,9103,9199-9200,9370,9876-9877,9950,10000,10080,11487,16086,16402,16420,16430,16433,16449,16498,16503,16545,16548,16573,16674,16680,16697,16700,16708,16711,16739,16766,16779,16786,16816,16829,16832,16838-16839,16862,16896,16912,16918-16919,16938-16939,16947-16948,16970,16972,16974,17006,17018,17077,17091,17101,17146,17184-17185,17205,17207,17219,17236-17237,17282,17302,17321,17331-17332,17338,17359,17417,17423-17424,17455,17459,17468,17487,17490,17494,17505,17533,17549,17573,17580,17585,17592,17605,17615-17616,17629,17638,17663,17673-17674,17683,17726,17754,17762,17787,17814,17823-17824,17836,17845,17888,17939,17946,17989,18004,18081,18113,18134,18156,18228,18234,18250,18255,18258,18319,18331,18360,18373,18449,18485,18543,18582,18605,18617,18666,18669,18676,18683,18807,18818,18821,18830,18832,18835,18869,18883,18888,18958,18980,18985,18987,18991,18994,18996,19017,19022,19039,19047,19075,19096,19120,19130,19140-19141,19154,19161,19165,19181,19193,19197,19222,19227,19273,19283,19294,19315,19322,19332,19374,19415,19482,19489,19500,19503-19504,19541,19600,19605,19616,19624-19625,19632,19639,19647,19650,19660,19662-19663,19682-19683,19687,19695,19707,19717-19719,19722,19728,19789,19792,19933,19935-19936,19956,19995,19998,20003-20004,20019,20031,20082,20117,20120,20126,20129,20146,20154,20164,20206,20217,20249,20262,20279,20288,20309,20313,20326,20359-20360,20366,20380,20389,20409,20411,20423-20425,20445,20449,20464-20465,20518,20522,20525,20540,20560,20665,20678-20679,20710,20717,20742,20752,20762,20791,20817,20842,20848,20851,20865,20872,20876,20884,20919,21000,21016,21060,21083,21104,21111,21131,21167,21186,21206-21207,21212,21247,21261,21282,21298,21303,21318,21320,21333,21344,21354,21358,21360,21364,21366,21383,21405,21454,21468,21476,21514,21524-21525,21556,21566,21568,21576,21609,21621,21625,21644,21649,21655,21663,21674,21698,21702,21710,21742,21780,21784,21800,21803,21834,21842,21847,21868,21898,21902,21923,21948,21967,22029,22043,22045,22053,22055,22105,22109,22123-22124,22341,22692,22695,22739,22799,22846,22914,22986,22996,23040,23176,23354,23531,23557,23608,23679,23781,23965,23980,24007,24279,24511,24594,24606,24644,24854,24910,25003,25157,25240,25280,25337,25375,25462,25541,25546,25709,25931,26407,26415,26720,26872,26966,27015,27195,27444,27473,27482,27707,27892,27899,28122,28369,28465,28493,28543,28547,28641,28840,28973,29078,29243,29256,29810,29823,29977,30263,30303,30365,30544,30656,30697,30704,30718,30975,31059,31073,31109,31189,31195,31335,31337,31365,31625,31681,31731,31891,32345,32385,32528,32768-32780,32798,32815,32818,32931,33030,33249,33281,33354-33355,33459,33717,33744,33866,33872,34038,34079,34125,34358,34422,34433,34555,34570,34577-34580,34758,34796,34855,34861-34862,34892,35438,35702,35777,35794,36108,36206,36384,36458,36489,36669,36778,36893,36945,37144,37212,37393,37444,37602,37761,37783,37813,37843,38037,38063,38293,38412,38498,38615,39213,39217,39632,39683,39714,39723,39888,40019,40116,40441,40539,40622,40708,40711,40724,40732,40805,40847,40866,40915,41058,41081,41308,41370,41446,41524,41638,41702,41774,41896,41967,41971,42056,42172,42313,42431,42434,42508,42557,42577,42627,42639,43094,43195,43370,43514,43686,43824,43967,44101,44160,44179,44185,44190,44253,44334,44508,44923,44946,44968,45247,45380,45441,45685,45722,45818,45928,46093,46532,46836,47624,47765,47772,47808,47915,47981,48078,48189,48255,48455,48489,48761,49152-49163,49165-49182,49184-49202,49204-49205,49207-49216,49220,49222,49226,49259,49262,49306,49350,49360,49393,49396,49503,49640,49968,50099,50164,50497,50612,50708,50919,51255,51456,51554,51586,51690,51717,51905,51972,52144,52225,52503,53006,53037,53571,53589,53838,54094,54114,54281,54321,54711,54807,54925,55043,55544,55587,56141,57172,57409-57410,57813,57843,57958,57977,58002,58075,58178,58419,58631,58640,58797,59193,59207,59765,59846,60172,60381,60423,61024,61142,61319,61322,61370,61412,61481,61550,61685,61961,62154,62287,62575,62677,62699,62958,63420,63555,64080,64481,64513,64590,64727,65024'
            $nmap = "$output/nmap-overall.xml"
            if($udp){
                if($ExcludeComputerList){
                    nmap -sU -T4 -n -v --open -oA $output/nmap-overall --min-parallelism $min_paralell --min-hostgroup $min_hostgroup -p $top1000  -iL $ComputerList --excludefile $ExcludeComputerList
                }else{
                    nmap -sU -T4 -n -v --open -oA $output/nmap-overall --min-parallelism $min_paralell --min-hostgroup $min_hostgroup -p $top1000  -iL $ComputerList
                }
            }else{
                if($ExcludeComputerList){
                    nmap -sS -T4 -n -v --open -oA $output/nmap-overall --min-parallelism $min_paralell --min-hostgroup $min_hostgroup -p- -iL $ComputerList --excludefile $ExcludeComputerList
                }else{
                    nmap -sS -T4 -n -v --open -oA $output/nmap-overall --min-parallelism $min_paralell --min-hostgroup $min_hostgroup -p- -iL $ComputerList
                }
            }
        }

        #Parsing big nmap scan into invidual .xml reports for each host
        Write-Output "`n[*] Starting Nmap XML Parsing"
        New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output/machines | Out-Null
        $header='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun> 
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>                                                                                                                 
<nmaprun>                                                                                                                                                                                        
<scaninfo/>                    
<verbose/>                            
<debugging/>'
        $footer='<runstats>
<finished/>
<hosts/>
</runstats>
</nmaprun>'
        try{
            [xml]$nmap_overall=Get-Content $nmap -ErrorAction Stop
        }catch{
            Write-Output "[-] Could not open $nmap"
            Write-Output "[-] $($_.Exception.Message)"
            return
        }
        $nmap_xml = $nmap_overall.nmaprun.host
        foreach($scan in $nmap_xml){
            $hostname = $scan.hostnames.hostname.name
            if(!$hostname){
                $hostname = $scan.address.addr
            }
            New-Item -ItemType Directory -ErrorAction SilentlyContinue $Output/machines/$hostname | Out-Null
            $report = $header + $scan.OuterXml + $footer
            add-Content -Value $report -Path $output/machines/$hostname/nmap.xml
        }

        $scanblock = {
            param(
                $machine
            )
            function local:Get-DefaultPassword{
                <#
                .SYNOPSIS
                Author: Cube0x0
                License: BSD 3-Clause

                Uses html parsing so if website changes anything, it may break

                .PARAMETER Path
                Path to offline database

                .PARAMETER Vendor
                Vendor or product to search for

                .EXAMPLE
                PS /root/LogonTracer> Get-DefaultPassword d-link                                                                                                                        
                Product  : D-Link 1. D-Link - 604                                                                                                                                       
                Version  :                                                                                                                                                              
                Method   : Telnet                                                                                                                                                       
                Username : Admin                                                                                                                                                        
                Password : (none)                                                                                                                                                       
                Level    : Administrator                                                                                                                                                
                Doc      :                                                                                                                                                              

                Product  : D-Link 2. D-Link - DCS-2121                                                                                                                                  
                Version  : 1.04                                                                                                                                                         
                Method   :                                                                                                                                                              
                Username : root                                                                                                                                                         
                Password : admin                                                                                                                                                        
                Level    : Administrator                                                                                                                                                
                Doc      : http://newsoft-tech.blogspot.com/2010/09/d-link-dcs-2121-and-state-of-embedded.html                                                                          
                           http://newsoft-tech.blogspot.com/2010/09/d-link-dcs-2121-and-state-of-embedded.html 
                #>
                [CmdletBinding()]
    	        param(
                    [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]
                    $vendor,

                    [string]$Path = "$(Get-Location)/Database.csv",

                    [switch]$Offline
                )
                begin{
                    if($Offline){
                        if(-not(Test-Path $Path)){
                            Write-Output "[-] Could not find offline Database"
                            return
                        }
                    }
                    if(-not(Get-Module PowerHTML -ListAvailable)){
                        Write-Output "[-] Install-module PowerHTML -force"
                        return
                    }
                    try{
                        Import-Module PowerHTML -ErrorAction stop
                    }catch{
                        Write-Output "[-] Could not import PowerHTML"
                        return
                    }
                }
                process{
                    if($offline){
                        try{
                            $database = Import-Csv $Path
                        }catch{
                            Write-Output "[-] Could not import csv"
                        }
                        $database | Where-Object -Property Product -match $vendor
                    }else{
                        try{
                            $html = (Invoke-WebRequest "https://cirt.net/passwords?criteria=$vendor" -ErrorAction stop | ConvertFrom-Html)
                        }catch{
                            Write-Output "[-] Could not connect to cirt.net"
                            Write-Output "[-] $($_.Exception.Message)"
                            return
                        }
                        $tables = $html.SelectNodes('//table').outerhtml
    	                foreach($table in $tables){
    	                	$list = ($table | Convertfrom-html).selectnodes('//tr/td').innerhtml
    	                	[pscustomobject]@{
                                Product  = [string]($list | Select-String -Pattern '<H3><B>' -Context 0,1).line.replace('<a name="','').Replace('"></a><h3><b>',' ').replace('&nbsp;','').Replace('<i>','').Replace('</i><b></b></b></h3>','')
                                Version  = [string]($list | Select-String -Pattern '<B>Version</B>' -Context 0,1).Context.PostContext
    	                		Method	 = [string]($list | Select-String -Pattern '<B>Method</B>' -Context 0,1).Context.PostContext
    	                		Username = [string]($list | Select-String -Pattern '<B>User ID</B>' -Context 0,1).Context.PostContext
    	                		Password = [string]($list | Select-String -Pattern '<B>Password</B>' -Context 0,1).Context.PostContext
    	                		Level	 = [string]($list | Select-String -Pattern '<B>Level</B>' -Context 0,1).Context.PostContext
    	                		Doc 	 = [string]($list | Select-String -Pattern '<B>Doc</B>' -Context 0,1).Context.PostContext.replace('<a href="','').replace('"></a>','').replace('</a>','').replace('">',' ')
    	                	}
                        }
                    }
                }
            } 
            $nmap_script = New-Object System.Collections.ArrayList
            $path = $machine.FullName
            $computer = $machine.Name
            Get-Date | Add-Content -Path $path/date.txt
            
            #check for open ports
            [xml]$xml = Get-Content $path/nmap.xml
            $hash=@{}
            Remove-Variable -Name tcp_* -Scope Script
            Remove-Variable -Name udp_* -Scope Script
            $hash.add('tcp',@())
            $hash.add('udp',@())
            foreach($i in $xml.nmaprun.host.ports.port){
                if([string]$i.childnodes.state -match 'open'){
                    if($i.protocol -match 'tcp'){
                        $hash.tcp += $i.portid
                    }else{
                        $hash.udp += $i.portid
                    }
                }
            }
            $open_ports = New-Object PSObject -Property $hash
            $open_ports.tcp | ForEach-Object {new-variable "tcp_$_" -Value $true -Scope Script}
            $open_ports.udp | ForEach-Object {new-variable "udp_$_" -Value $true -Scope Script}

            if($tcp_21){
                #ftp
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/ftp | Out-Null
                    hydra -C ./wordlist/ftp-default-userpass.txt $computer ftp -t $threads -e ns | tee -a $path/ftp/hydra.txt
                    hydra -L ./wordlist/ftp_defuser.lst -P ./wordlist/ftp_defpass.lst $computer ftp -t $threads -e ns | tee -a $path/ftp/hydra.txt
                }
            }
            if($tcp_22){
                #ssh
                if($Misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/ssh | Out-Null
                    ssh-audit $computer | tee -a $path/ssh/ssh-audit.txt
                }
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/ssh | Out-Null
                    hydra -C ./wordlist/ssh-default-userpass.txt $computer ssh -t 4 -e ns | tee -a $path/ssh/hydra.txt
                    hydra -L ./wordlist/ssh_defuser.lst -P ./wordlist/ssh_defpass.lst $computer ssh -t 4 -e ns | tee -a $path/ssh/hydra.txt
                }
            }
            if($tcp_23){
                #telnet
                'telnet-encryption' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/telnet | Out-Null
                    hydra -C ./wordlist/telnet-default-userpass.txt $computer telnet -t $threads -e ns | tee -a $path/telnet/hydra.txt
                    hydra -L ./wordlist/telnet_defuser.lst -P ./wordlist/telnet_defpass.lst $computer telnet -t $threads -e ns | tee -a $path/telnet/hydra.txt
                }
            }
            if($tcp_25){
                #smtp
                'smtp-open-relay' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/smtp | Out-Null
                    hydra -L ./wordlist/smtp_defuser.lst -P ./wordlist/smtp_defpass.lst $computer smtp -t $threads -e ns | tee -a $path/smtp/hydra.txt
                }
            }
            if($tcp_53){}
            if($tcp_79){
                #finger            
            }
            if($tcp_80){
                #http
                'http-config-backup','http-iis-short-name-brute','http-default-accounts','http-devframework','http-headers','http-internal-ip-disclosure','http-php-version','http-security-headers','http-server-header','http-userdir-enum','http-waf-detect','http-waf-fingerprint' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($Web){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/http | Out-Null
                    nikto -h "http://$computer" -output $path/http/nikto.txt
                    wafw00f -a "http://$computer" | tee -a $path/http/wafw00f.txt
                    cutycapt --url=http://$computer --out=$path/http/index.jpg --max-wait=5000
                    @(
                        "wp-content"
                        "wordpress/wp-content"
                        "wp/wp-content"
                        "wp/wordpress"
                    ) | ForEach-Object {
                        try{
                            $wp=(Invoke-WebRequest https://$computer/$_ -ErrorAction Stop)
                        }catch{}
                    }
                    if($wp){
                        wpscan --url ($wp.BaseResponse.RequestMessage.RequestUri.AbsoluteUri).replace('wp-content','') --enumerate ap --no-update | tee -a $path/http/wpscan.txt
                    }
                }
                if($BurpSuite){
                    $data = '{"""urls""":["""http://replaceme:80/"""]}'.Replace('replaceme',$computer)
                    curl -vgw "\n" -X POST 'http://localhost:1337/v0.1/scan' -d $data
                }
            }
            if($tcp_110){
                #pop3
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/pop3 | Out-Null
                    hydra -L ./wordlist/pop_defuser.lst -P ./wordlist/pop_defpass.lst $computer pop -t $threads -e ns | tee -a $path/pop3/hydra.txt
                }
            }
            if($tcp_111){
                #nfs
                'nfs-ls','nfs-showmount','nfs-statfs' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($MetaSploit){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/nfs | Out-Null
                    msfconsole -q -x "use auxiliary/scanner/nfs/nfsmount; set RHOSTS $computer ;set PROTOCOL tcp; run; ;set PROTOCOL udp; run; back; exit;" | tee -a $path/nfs/msf.txt
                }
                if($Misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/nfs | Out-Null
                    showmount -a $computer | tee -a $path/nfs/showmount.txt
                    showmount -d $computer | tee -a $path/nfs/showmount.txt
                    showmount -e $computer | tee -a $path/nfs/showmount.txt
                }
            }
            if($tcp_135){
                #rpc
            }
            if($tcp_137){
                #netbios
                'broadcast-netbios-master-browser' | ForEach-Object {$nmap_script.add($_) | Out-Null}
            }
            if($tcp_139){
                #netbios
                if($MetaSploit){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/netbios | Out-Null
                    msfconsole -q -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS $computer; setg RHOST $computer; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;" | tee -a $path/netbios/msf.txt
                }
            }
            if($tcp_162){
                #snmp
                'snmp-ios-config' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/snmp | Out-Null
                    hydra -P ./wordlist/snmp-strings.txt $computer snmp -S 162 -t $threads -e ns | tee -a $path/snmp/hydra.txt
                }
            }
            if($tcp_389){
                #ldap
                #if($Misc){
                #    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/ldap | Out-Null
                #    ldapsearch -x -h $computer -p 389 -s base '(objectclass=*)' | tee -a $path/ldap/ldapsearch.txt
                #}
            }
            if($tcp_443){
                #https
                'http-config-backup','http-iis-short-name-brute','http-default-accounts','http-devframework','http-headers','http-internal-ip-disclosure','http-php-version','http-security-headers','http-server-header','http-userdir-enum','http-waf-detect','http-waf-fingerprint' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($Web){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/https | Out-Null
                    nikto -h "https://$computer" -output $path/https/nikto.txt
                    wafw00f -a "https://$computer" | tee -a $path/https/wafw00f.txt
                    sslscan $computer
                    cutycapt --url=https://$computer --out=$path/https/$computer-port80.jpg --insecure --max-wait=5000
                    @(
                        "wp-content"
                        "wordpress/wp-content"
                        "wp/wp-content"
                        "wp/wordpress"
                    ) | ForEach-Object {
                        try{
                            $wp=(Invoke-WebRequest https://$computer/$_ -ErrorAction Stop)
                        }catch{}
                    }
                    if($wp){
                        wpscan --url ($wp.BaseResponse.RequestMessage.RequestUri.AbsoluteUri).replace('wp-content','') --enumerate ap --no-update --disable-tls-checks | tee -a $path/https/wpscan.txt
                    }
                }
                if($BurpSuite){
                    $data = '{"""urls""":["""https://replaceme:443/"""]}'.Replace('replaceme',$computer)
                    curl -vgw "\n" -X POST 'http://localhost:1337/v0.1/scan' -d $data
                }
            }
            if($tcp_445){
                #smb
                if($MetaSploit){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/smb | Out-Null
                    msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS $computer; run; exit;" | tee -a $path/smb/msf.txt
                }
                if($Misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/smb | Out-Null
                    New-Item -ItemType File $path/smb/smbclient.auto | Out-Null
                    Write-Output "shares" > $path/smb/smbclient.auto
                    Write-Output "exit" >> $path/smb/smbclient.auto
                    Write-Output "`n[*] Trying Null, Anonymous and Guest Logon" | tee -a $path/smb/null-anon-guest.txt
                    Write-Output "`nsmbclient.py @$computer -no-pass -f" | tee -a $path/smb/null-anon-guest.txt
                    smbclient.py @$computer -no-pass -f $path/smb/smbclient.auto | tee -a $path/smb/null-anon-guest.txt
                    Write-Output "`nsmbclient.py anonymous@$computer -no-pass" | tee -a $path/smb/null-anon-guest.txt
                    smbclient.py anonymous@$computer -no-pass -f $path/smb/smbclient.auto | tee -a $path/smb/null-anon-guest.txt
                    Write-Output "`nsmbclient.py guest@$computer -no-pass" | tee -a $path/smb/null-anon-guest.txt
                    smbclient.py guest@$computer -no-pass -f $path/smb/smbclient.auto | tee -a $path/smb/null-anon-guest.txt
                }
            }
            if($tcp_512){
                #rexec
            }
            if($tcp_513){
                #rlogin
            }
            if($tcp_514){}
            if($tcp_623){}
            if($tcp_624){}
            if($tcp_993){
                #imap
            }
            if($tcp_1099){
                #rmi
                if($MetaSploit){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/rmi | Out-Null
                    msfconsole -q -x "use gather/java_rmi_registry; set RHOST $computer; run; exit;" | tee -a $path/rmi/msf.txt
                    msfconsole -q -x "use scanner/misc/java_rmi_server; set RHOST $computer; run; exit;" | tee -a $path/rmi/msf.txt
                }
            }
            if($tcp_1433){
                #mssql
                'ms-sql-empty-password' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($MetaSploit){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/mssql | Out-Null
                    msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; setg RHOSTS $computer; run; back; exit;" | tee -a $path/mssql/msf.txt
                }
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/mssql | Out-Null
                    hydra -C ./wordlist/mssql-default-userpass.txt $computer mysql -t $threads -e ns | tee -a $path/mssql/hydra.txt
                }
            }
            if($tcp_1521){
                #oracle
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/oracle | Out-Null
                    hydra -C ./wordlist/oracle-default-userpass.txt $computer oracle -S 1521 -t $threads -e ns | tee -a $path/oracle/hydra.txt
                }
            }
            if($tcp_1524){}
            if($tcp_2049){
                #nfs
                'nfs-statfs','nfs-showmount','nfs-ls' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($Misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/nfs | Out-Null
                    showmount -e $computer | tee -a $path/nfs/showmount.txt
                }
            }
            if($tcp_2121){}
            if($tcp_3128){}
            if($tcp_3306){
                #mysql
                'mysql-empty-password' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/mysql | Out-Null
                    hydra -C ./wordlist/mysql-default-userpass.txt $computer mysql -t $threads -e ns | tee -a $path/mysq/hydra.txt
                }
                
            }
            if($tcp_3310){
                #ClamAV
                'clamav-exec' | ForEach-Object {$nmap_script.add($_) | Out-Null}
            }
            if($tcp_3389){
                #rdp
            }
            if($tcp_3632){}
            if($tcp_4443){}
            if($tcp_5060){
                #voip
                if($misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/voip | Out-Null
                    svmap -p5060 $computer | tee -a $path/voip/svmap.txt
                    svwar -D -m INVITE -p5061 $computer | tee -a $path/voip/svwar.txt
                }
            }
            if($tcp_5061){
                #voip
                if($misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/voip | Out-Null
                    svmap -p5061 $computer | tee -a $path/voip/svmap.txt
                    svwar -D -m INVITE -p5061 $computer | tee -a $path/voip/svwar.txt
                }
            }
            if($tcp_5062){
                #voip
                if($misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/voip | Out-Null
                    svmap -p5062 $computer | tee -a $path/voip/svmap.txt
                    svwar -D -m INVITE -p5062 $computer | tee -a $path/voip/svwar.txt
                }
            }
            if($tcp_5038){
                #Asterisk Call Manager
                if($misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/voip | Out-Null
                    svmap -p5038 $computer | tee -a $path/voip/svmap.txt
                    svwar -D -m INVITE -p5038 $computer | tee -a $path/voip/svwar.txt
                }
            }
            if($tcp_5432){
                #postgresql
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/postgres | Out-Null
                    hydra -C ./wordlist/postgres-default-userpass.txt $computer postgres -t $threads -e ns | tee -a $path/postgres/hydra.txt
                }
            }
            if($tcp_5555){}
            if($tcp_5800){}
            if($tcp_5900){
                #vnc
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/vnc | Out-Null
                    hydra -p ./wordlist/vnc-default-pass.txt $computer postgres -s 5900 -t $threads -e ns | tee -a $path/vnc/hydra.txt
                }
            }
            if($tcp_5901){
                #vnc
                if($Hydra){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/vnc | Out-Null
                    hydra -p ./wordlist/vnc-default-pass.txt $computer postgres -s 59001 -t $threads -e ns | tee -a $path/vnc/hydra.txt
                }
            }
            if($tcp_5984){}
            if($tcp_6667){
                #irc
            }
            if($tcp_7001){}
            if($tcp_8000){}
            if($tcp_8080){}
            if($tcp_8180){}
            if($tcp_8443){}
            if($tcp_8888){}
            if($tcp_9200){}
            if($tcp_9495){}
            if($tcp_10000){}
            if($tcp_16992){}
            if($tcp_27017){}
            if($tcp_27018){}
            if($tcp_27019){}
            if($tcp_28017){}
            if($tcp_49180){}
            if($tcp_49152){}
            #udp ports
            if($udp_67){
                #dhcp
                'dhcp-discover' | ForEach-Object {$nmap_script.add($_) | Out-Null}
            }
            if($udp_68){
                #dhcp
                'dhcp-discover' | ForEach-Object {$nmap_script.add($_) | Out-Null}
            }
            if($udp_69){
                #tftp
                'tftp-enum' | ForEach-Object {$nmap_script.add($_) | Out-Null}
            }
            if($udp_123){
                #ntp
                'ntp-monlist' | ForEach-Object {$nmap_script.add($_) | Out-Null}
            }
            if($udp_161){
                #snmp
                'snmp-ios-config' | ForEach-Object {$nmap_script.add($_) | Out-Null}
                if($MetaSploit){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/smtp | Out-Null
                    msfconsole -q -x "use scanner/snmp/snmp_enum; setg RHOSTS $computer; run; exit;" | tee -a $path/smtp/msf.txt
                }
            }
            if($udp_500){
                #ike
                if($Misc){
                    New-Item -ItemType Directory -ErrorAction SilentlyContinue $path/ike | Out-Null
                    ike-scan $computer | tee -a $path/ike/ike-scan.txt
                    ike-scan $computer -M -A --id=fake -P | tee -a $path/ike/ike-scan.txt
                }
            }
            'vuln' | ForEach-Object {$nmap_script.add($_) | Out-Null}
            $nmap_script=$nmap_script -join ','
            if($udp){
                $udp_ports=$open_ports.udp -join ','
                nmap -sU -sC -sV -n -Pn -p $udp_ports --script=$nmap_script -oA $path/nmap-scriptscan $computer
            }else{
                $tcp_ports=$open_ports.tcp -join ','
                nmap -sS -sC -sV -n -Pn -p $tcp_ports --script=$nmap_script -oA $path/nmap-scriptscan $computer
            }
            try{
                [xml]$services = (Get-Content $path/nmap-scriptscan.xml)
            }catch{
                Write-Output "`n[-]Nmap Segmentation fault may occurred on $computer"
                Add-Content -Value "Nmap Segmentation fault while script scanning may occurred on $computer" -Path $path/../../error.txt
            }
            if($services){
                Write-Output "`n[*] Creating Searchsploit Report"
                searchsploit -v --nmap $path/nmap-scriptscan.xml 2>&1 | tee -a $path/searchsploit.txt
                Write-Output "`n[*] Looking up default password for each product"
                $services.nmaprun.host.ports.port.service | where {$_.product}  | foreach {
                    $product = $_.product.tostring()
                    try{
                        Get-DefaultPassword $product -offline -ErrorAction SilentlyContinue
                        Get-DefaultPassword ($product.split(' ')[0]) -offline -ErrorAction SilentlyContinue
                        Get-DefaultPassword ($product.split(' ')[0..1]) -offline -ErrorAction SilentlyContinue
                        Get-DefaultPassword ($product.split(' ')[1]) -offline -ErrorAction SilentlyContinue
                    }catch{}
                } | Out-File -path $path/defaultpass.txt
            }
        }#end of script scanning script block
        
        #start one scanning job per machine
        Write-Output "[*] Starting scanning jobs $(get-date)"
        (Get-ChildItem $output\machines\) | Start-RSJob -ScriptBlock $scanblock -ArgumentList $_ -ModulesToImport PowerHTML | Out-Null
        #Get-RSJob | Wait-RSJob -ShowProgress
        #Write-Output "[*] Scanning completed"
        #get-date
    }
}