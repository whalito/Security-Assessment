function ConvertFrom-CisHtml{
    param(
        [CmdletBinding()]
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [ValidateScript({Test-Path -Path $_ })]
        $html,

        [Parameter(Mandatory=$true, Position=1)]
        $output
    )
    if(get-module PSWriteWord -ListAvailable){
        import-module PSWriteWord
    }else{
        Write-Output "install-module PSWriteWord"
        throw
    }
    $html = Get-Content $html -Raw
    $rep = New-Object -com "HTMLFILE"
    $rep.IHTMLDocument2_write($html)
    $WordDocument = New-WordDocument $output
    $count = 0
    foreach($i in ($rep.body.getElementsByClassName('Rule'))){
        $doc = New-Object -com "HTMLFILE"
        $doc.IHTMLDocument2_write(($i | select -ExpandProperty innerhtml))
        $res = ($doc.body.getElementsByClassName('outcome') | select -ExpandProperty outertext)
        if(($res) -and ($res -notmatch 'pass')){
            $count +=1
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Issue:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text ($doc.body.getElementsByClassName('ruleTitle') | select -ExpandProperty outertext)
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Observation:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text (($doc.body.getElementsByClassName('description') | where {$_.outerhtml -match '<DIV class=bold>Description:</DIV>'}).outertext.replace('Description:','').trim())
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Impact:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text ($doc.body.getElementsByClassName('rationale') | select -ExpandProperty outertext)
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Bold $true -Supress $True -Text 'Recommendation:'
            Add-WordText -WordDocument $WordDocument -FontSize 12 -SpacingBefore 15 -Supress $True -Text ($doc.body.getElementsByClassName('fixtext') | select -ExpandProperty outertext)
        }
    }
    $out = Save-WordDocument $WordDocument -Language 'en-US'
    Write-Output "Found $count improvements"
    Write-Output "saved to $out"
}