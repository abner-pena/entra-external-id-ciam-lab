<#
.SYNOPSIS
    Pulls Microsoft Entra ID Protection risky user and risk detection records
    scoped to the External ID (CIAM) tenant and exports them to CSV.

.DESCRIPTION
    In a workforce tenant, risky sign-in reports usually go to a SOC analyst.
    In a CIAM tenant, the consumer of this same data is often a fraud or
    trust-and-safety analyst instead, so this script is written to produce a
    flat export rather than a SOC-style triage queue.

.PARAMETER MinimumRiskLevel
    Lowest risk level to include: low, medium, or high. Defaults to medium.

.PARAMETER OutputPath
    CSV output path. Defaults to ./external-user-risk-export.csv

.EXAMPLE
    ./Audit-ExternalUserRiskySignins.ps1 -MinimumRiskLevel medium -OutputPath ./risk-export.csv
#>

[CmdletBinding()]
param(
    [ValidateSet("low", "medium", "high")]
    [string]$MinimumRiskLevel = "medium",

    [string]$OutputPath = "./external-user-risk-export.csv"
)

$ErrorActionPreference = "Stop"

Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All", "IdentityRiskEvent.Read.All" -NoWelcome

$riskRank = @{ low = 0; medium = 1; high = 2 }
$threshold = $riskRank[$MinimumRiskLevel]

Write-Host "Pulling risky users at or above '$MinimumRiskLevel' risk..." -ForegroundColor Cyan
$riskyUsers = Get-MgRiskyUser -All | Where-Object {
    $riskRank.ContainsKey($_.RiskLevel) -and $riskRank[$_.RiskLevel] -ge $threshold
}

Write-Host "Pulling risk detections..." -ForegroundColor Cyan
$riskDetections = Get-MgRiskDetection -All

$results = foreach ($user in $riskyUsers) {
    $detections = $riskDetections | Where-Object { $_.UserId -eq $user.Id }
    foreach ($detection in $detections) {
        [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            UserId            = $user.Id
            RiskLevel         = $user.RiskLevel
            RiskState         = $user.RiskState
            DetectionType     = $detection.RiskEventType
            DetectionDateTime = $detection.DetectedDateTime
            IpAddress         = $detection.IpAddress
            Location          = "$($detection.Location.City), $($detection.Location.CountryOrRegion)"
            Source            = $detection.Source
        }
    }
}

if (-not $results) {
    Write-Host "No risk detections found at or above '$MinimumRiskLevel' for the queried window." -ForegroundColor Yellow
    return
}

$results | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "Exported $($results.Count) risk detection records to $OutputPath" -ForegroundColor Green
Write-Host "Hand this export to the fraud or trust-and-safety team, not just the SOC," -ForegroundColor Cyan
Write-Host "since CIAM risk signal usually feeds a different response process than workforce risk." -ForegroundColor Cyan
