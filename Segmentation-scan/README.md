PS > Import-Module .\Segmentation-scan.psd1


PS > Get-Command -Module Segmentation-scan
```
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Get-NmapIP                                         1.0        Segmentation-scan
Function        Get-NmapPort                                       1.0        Segmentation-scan
Function        Get-AddressOverview                                1.0        Segmentation-scan
Function        Get-ServiceOverview                                1.0        Segmentation-scan
Function        Get-UndocumentedAddresses                          1.0        Segmentation-scan
Function        Get-UndocumentedServices                           1.0        Segmentation-scan
```

.Example how to generate CSV files with undocumented ips and port
```
PS > Get-AddressOverview -xml nmap-scan.xml,nmap-scan2.xml -output AddressOverview.csv -dns dnsserver.hackme.local
PS > Get-UndocumentedAddresses -CSV AddressOverview.csv -output UndocumentedAddresses.csv -ReferenceAddresses ips.txt
```
```
PS > Get-ServiceOverview -xml  nmap-scan.xml,nmap-scan2.xml -output ServiceOverview.csv -dns dnsserver.hackme.local
PS > Get-UndocumentedServices -CSV ServiceOverview.csv -output UndocumentedServices -ReferencePorts 161,123,443
```
