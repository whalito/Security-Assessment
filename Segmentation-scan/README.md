PS > Import-Module .\Segmentation-scan.psd1


PS > Get-Command -Module Segmentation-scan
````
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Get-NmapIP                                         1.0        Segmentation-scan
Function        Get-NmapPort                                       1.0        Segmentation-scan
Function        Get-SegmentationOverview                           1.0        Segmentation-scan
Function        Get-SegmentationOverview2                          1.0        Segmentation-scan
Function        Get-SegmentationReport                             1.0        Segmentation-scan
```

.Example
PS > Get-SegmentationOverview -xml nmap-scan.xml,nmap-scan2.xml -output overview.csv -dns dnsserver.hackme.local
PS > Get-SegmentationOverview2 -xml nmap-scan.xml,nmap-scan2.xml -output overview2.csv -dns dnsserver.hackme.local
PS > Get-SegmentationReport -csv overview.csv,overview2.scv -ReferenceIps ips.txt -ReferencePorts 80,443 -output report.csv
