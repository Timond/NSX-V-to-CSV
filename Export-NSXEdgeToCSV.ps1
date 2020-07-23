<#
.SYNOPSIS
  Script to export NSX Edge sections to .CSV

.DESCRIPTION
 
.EXAMPLE
  
.NOTES
  Version:        0.1
  Author:         Tim Duncan
  Creation Date:  23/7/2020
  Purpose/Change: Initial Commit
 
.NOTES
	REQUIRES: PowerCLI & PowerNSX 
	VERSION - 0.1
 
	Please use version control panel to trace versions & forks.
	Name			Date		Version		Details
	--------------------------------------------------------------------------
    Tim Duncan   23/7/2020	0.1			Created Script
 
.LINK
	n/a
 
#>

param (
    #Example: myvcenter.mydomain.com
    [Parameter(Mandatory=$true)][string]$vCenterURL,
    #Example: edge-123
    [Parameter(Mandatory=$true)][string]$EdgeID,
    #Pass in a credential object containing vCenter SSO logins
    [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential,
    #Create CSV containing firewall rules
    [switch]$Firewall = $true,
    #Create CSV containing nat rules
    [switch]$Nat = $true,
    #Create CSV containing used IPset details
    [switch]$IPsets = $true,
    #Directory to save CSV to
    [string]$ExportPath = (Get-Location).path + "\"
)

function Export-NSXEdgeFirewallToCsv() {
    param (
        [Parameter(Mandatory=$true)][System.Xml.XmlElement]$Edge
    )

    $EdgeFirewall = Get-NsxEdgeFirewall -Edge $Edge
    $EdgeFirewallRules = $EdgeFirewall.firewallRules
    $FirewallCSV = New-Object -TypeName "System.Collections.Arraylist"
    $Progress = 0
    $EdgeIPSets = Get-NsxIpSet -scopeId $Edge.id

    $EdgeFirewallRules.firewallRule | % {
        $Rule = $_

        #Source
        $SourceExclude = $rule.source.exclude
        $SourceString = ""
        if ($Rule.source){
            $SourceCount = 1
            $Rule.source.ipAddress | % {
                $SourceString += "$($_)"
                if ($SourceCount -lt $Rule.source.ipAddress.Count) {
                    $SourceString += "`n"
                }
                $SourceCount++
            }
        } 
        
        if ($Rule.source.groupingObjectId) {
            $SourceCount = 1
            if ($SourceString.Length -gt 0) { $SourceString += "`n" }
            $Rule.source.groupingObjectId | % {
                $GroupingObject = $EdgeIPSets | Where-Object -Property objectId -eq $_
                $SourceString += $GroupingObject.name.Split(":")[1]
                if ($SourceCount -lt $rule.source.groupingObjectId.Count) {
                    $SourceString += "`n"
                }
                $SourceCount++
            }
        }
        
        if ($SourceString.Length -eq 0) {
            $SourceString = "any"
        }

        #Destination
        $DestinationExclude = $Rule.destination.exclude
        $DestinationString = ""
        if ($Rule.Destination){
            $DestinationCount = 1
            $Rule.destination.ipAddress | % {
                $DestinationString += "$($_)"
                if ($DestinationCount -lt $Rule.destination.ipAddress.Count) {
                    $DestinationString += "`n"
                }
                $DestinationCount++
            }
        } else {
            $DestinationString = "any"
        }

        
        if ($Rule.destination.groupingObjectId) {
            $DestinationCount = 1
            if ($DestinationString.Length -gt 0) { $SourceString += "`n" }
            $Rule.destination.groupingObjectId | % {
                $GroupingObject = $EdgeIPSets | Where-Object -Property objectId -eq $_
                #$GroupingObject = Get-NsxIpSet -objectId $_
                $DestinationString += $GroupingObject.name.Split(":")[1]
                if ($DestinationCount -lt $rule.destination.groupingObjectId.Count) {
                    $DestinationString += "`n"
                }
                $DestinationCount++
            }
        }
        
        #Application / Service
        $ServiceCount = 1
        $ApplicationString = ""
        if($Rule.application){
            $Rule.application.service | % {
                $Protocol = $_.protocol
                $Port = $_.port
                $SourcePort = $_.sourcePort

                $ApplicationString += "$Protocol"
            
                $PortCount = 1
                $PortString = ""
                $Port | % {
                    $PortString += $_
                    if($PortCount -lt $Port.count){
                        $PortString += ","
                    } 
                    $PortCount ++
                }
                $ApplicationString += ":$PortString"

                $PortCount = 1
                $SourcePortString = ""
                $SourcePort | % {
                    $SourcePortString += $_
                    if($PortCount -lt $Port.count){
                        $PortString += ","
                    } 
                    $PortCount ++

                }
                $ApplicationString += ":$SourcePortString"

                if ($ServiceCount -lt $Rule.application.service.Count){
                    $ApplicationString += "`n"
                }
                $ServiceCount++
            }

        } else {
            $ApplicationString = "any"
        }
        
        $ProgressPercentage = [math]::Truncate(($progress / $EdgeFirewallRules.firewallRule.Count) * 100)
        Write-Progress -Activity "Adding lines to CSV" -Status "$ProgressPercentage complete" -PercentComplete $ProgressPercentage
        $FirewallCSV.Add(
        [PsCustomObject] @{
            "ID" = $Rule.id
            "Name" = $Rule.name
            "Type" = $Rule.ruleType
            "Enabled" = $Rule.enabled
            "LoggingEnabled" = $Rule.loggingEnabled
            "Description" = $Rule.description
            "Action" = $Rule.action
            "SourceExclude" = $SourceExclude
            "Source" = $SourceString
            "DestinationExclude" = $DestinationExclude
            "Destination" = $DestinationString
            "Protocol:Port:Sourceport" = $ApplicationString
        }) | Out-Null
        $Progress++
    }

    $FullPath = $ExportPath + $EdgeID + "-firewall-rules.csv"
    Write-Host "Exporting CSV to $FullPath" -ForegroundColor Yellow
    $FirewallCSV | Export-Csv -Path $FullPath -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green


}

function Export-NSXEdgeNatToCsv() {
    param (
        [Parameter(Mandatory=$true)][System.Xml.XmlElement]$Edge
    )
    $EdgeNat = Get-NsxEdgeNat -Edge $Edge
    $EdgeNatRules = $EdgeNat.natRules
    $NatCSV = New-Object -TypeName "System.Collections.Arraylist"
    $EdgeNatRules.natRule | % {
        $CSVLine = [PSCustomObject]@{
            "Description" = $_.description
            "RuleType" = $_.ruleType
            "vNic" = $_.vnic
            "Action" = $_.action
            "Dnat Source Address" = $_.dnatMatchSourceAddress
            "Dnat Source Port" = $_.dnatMatchSourcePort
            "Original Address" = $_.originalAddress
            "Protocol" = $_.protocol
            "Original Port" = $_.originalPort
            "Translated Address" = $_.translatedAddress
            "Translated Port" = $_.translatedPort
            "Snat Destination Address" = $_.snatMatchDestinationAddress
            "Snat Destination Port" = $_.snatMatchDestinationPort
            "Enabled" = $_.enabled
            "LoggingEnabled" = $_.loggingEnabled
        }
        $NatCSV.Add($CSVLine) | Out-Null
    }
    $FullPath = $ExportPath + $EdgeID + "-NAT-rules.csv"
    Write-Host "Exporting NAT CSV to $FullPath" -ForegroundColor Yellow
    $NatCSV | Export-Csv -Path $FullPath -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

function Export-IPsetsToCSV(){
    param (
        [Parameter(Mandatory=$true)][System.Xml.XmlElement]$Edge,
        #Parse Firewall and NAT rules, and only put used ipsets in CSV
        [switch]$UsedOnly = $false,
        [switch]$Summary = $true
    )

    #Get Firewall and Nat rules
    $EdgeFirewall = Get-NsxEdgeFirewall -Edge $Edge
    $EdgeFirewallRules = $EdgeFirewall.firewallRules
    $EdgeNat = Get-NsxEdgeNat -Edge $Edge
    $EdgeNatRules = Get-NsxEdgeNatRule -EdgeNat $EdgeNat

    $GroupingIds = New-Object -TypeName System.Collections.Arraylist
    
    $EdgeFirewallRules.firewallRule | % {
        if($_.source.groupingObjectId) {
            $_.source.groupingObjectId | % {
                $GroupingIds.Add($_) | Out-Null
            }
        }
        if($_.destination.groupingObjectId) {
            $_.destination.groupingObjectId | % {
                $GroupingIds.Add($_) | Out-Null
            }
        }
    }

    $IPsets = New-Object -TypeName System.Collections.Arraylist
    $GroupingIDs | Sort-Object -Unique | % {
        $IPset = Get-NsxIpSet -objectId $_
        $IPsets.add($IPset) | Out-Null
    }

    $FullPath = $ExportPath + $EdgeID + "-IPsets.csv"
    Write-Host "Exporting IPSet CSV to $FullPath" -ForegroundColor Yellow

    if($Summary){
        $IPsetCSV = New-Object -TypeName System.Collections.ArrayList
        $IPsets | % {
            $IPAddresses = ""
            $c = 1
            $IPArray = $_.value.Split(",")
            $IPArray | % {
                $IPAddresses += $_
                if ($c -lt $IPArray.count ) {
                    $IPAddresses += "`n"
                }
                $c++
            }

            $CsvLine = [PSCustomObject]@{
                "ObjectId" = $_.ObjectId
                "Name" = $_.name.Split(":")[1]
                "IPAddresses" = $IPAddresses
            }

            $IPsetCSV.Add($CsvLine) | Out-Null
        }

        $IPsetCSV | Export-Csv -Path $FullPath -NoTypeInformation
        Write-Host "Done" -ForegroundColor Green
    } else {
        $IPsets | Export-Csv -Path $FullPath -NoTypeInformation
        Write-Host "Done" -ForegroundColor Green
    }

}

#Connect to vCenter using powernsx
try {
    Connect-NsxServer -vCenterServer $vCenterURL -Credential $Credential -ErrorAction Stop
} 
catch {
    Write-Host "Unable to connect to $vCenterURL." -ForegroundColor Red
    $Error.exception
    return
}

#Try to get the NSX edge
try {
    Write-Host "Attempting to fetch edge $EdgeID" -ForegroundColor Yellow
    $Edge = Get-NsxEdge -objectId $EdgeID -ErrorAction Stop
    Write-Host "Success. Got edge $($Edge.name)" -ForegroundColor Green
}
catch {
    Write-Host "Unable to get edge $EdgeID" -ForegroundColor Red
    return
}

if($Firewall){
    Export-NSXEdgeFirewallToCsv -Edge $Edge
}

if ($IPsets){
    Export-IPsetsToCSV -Edge $Edge -UsedOnly:$true
}

if ($Nat){
    Export-NSXEdgeNatToCsv -Edge $Edge
}
