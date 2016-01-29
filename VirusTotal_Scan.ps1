function Get-VTReport {

Param(
    [parameter(Mandatory=$true)]
    [String]
    $URL
    )

$VirusTotalGet = "http://www.virustotal.com/vtapi/v2/url/report"

$postParams = @{resource="$URL";apikey='YOUR_API_KEY';scan='1'}

Invoke-WebRequest -Uri $VirusTotalGet -Method POST -Body $postParams

}

$errorcode=@()
$ReportArray=@()
$csv = import-csv "C:\scripts\VirusTotal_Scan\URLs.csv"

$i=0

foreach ($item in $csv) {

    $URL = $item.url

    $i++
    Write-Progress -activity “Checking URL” -status “$($URL)” -PercentComplete (($i / $csv.count)*100)

    $VTResult = Get-VTReport -URL $URL

    IF ($VTResult.statuscode -ne "200") 
        {
    
        $errorcode += "Query unsuccessful - $URL - $($VTResult.statuscode)"
        Write-Progress -activity “Query Unsuccessful. Waiting 17 seconds...” -status “$($URL)” -PercentComplete (($i / $csv.count)*100)
        Start-Sleep -s 17

        }

    ELSE {

        $VTResult = $VTResult | ConvertFrom-Json
        
        while ($($VTResult.verbose_msg) -eq "Scan request successfully queued, come back later for the report")
            {
            Write-Progress -activity “Scan Queued. Waiting 17 seconds...” -status “$($URL)” -PercentComplete (($i / $csv.count)*100)
            start-sleep -s 17
            $VTResult = Get-VTReport -URL $URL
            $VTResult = $VTResult | ConvertFrom-Json
            }

    
        IF ($VTResult.verbose_msg -eq "Scan finished, scan information embedded in this object")
            {
            $Positives = $VTResult.positives
            $Total = $VTResult.total
            $ScanDate = $VTResult.scan_date

            $ob = new-object psobject
            $ob | add-member -type NoteProperty -name URL -value "$($URL)"
            $ob | add-member -type NoteProperty -Name Positives -Value "$($Positives)"
            $ob | add-member -type NoteProperty -Name Total -Value "$($Total)"
            $ob | add-member -type NoteProperty -Name ScanDate -Value "$($ScanDate)"
            $Reportarray += $ob
            Write-Progress -activity “Scan Complete. Waiting 17 seconds before starting next...” -status “$($URL)” -PercentComplete (($i / $csv.count)*100)
            Start-Sleep -s 17
            }

    }
    
    start-sleep -s 20
}

$errorcode | out-file C:\scripts\VirusTotal_Scan\Logs.txt
$reportarray | export-csv C:\Scripts\VirusTotal_Scan\Results.csv -NoTypeInformation