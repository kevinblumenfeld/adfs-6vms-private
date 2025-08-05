# ARM Template API Version Analysis Script
# This script analyzes all ARM templates for API version consistency

Write-Host "🔍 ARM Template API Version Analysis" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan

$armFiles = Get-ChildItem -Path "." -Filter "*.json" | Where-Object { $_.Name -ne "azuredeploy.parameters.json" }

$apiVersionSummary = @{}
$inconsistencies = @()

foreach ($file in $armFiles) {
    Write-Host "`n📄 File: $($file.Name)" -ForegroundColor Yellow
    $content = Get-Content $file.FullName -Raw
    
    # Extract all API versions from the file
    $apiVersionMatches = [regex]::Matches($content, '"apiVersion":\s*"([^"]+)"')
    
    $fileApiVersions = @()
    foreach ($match in $apiVersionMatches) {
        $apiVersion = $match.Groups[1].Value
        $fileApiVersions += $apiVersion
        
        # Track all API versions globally
        if (-not $apiVersionSummary.ContainsKey($apiVersion)) {
            $apiVersionSummary[$apiVersion] = @()
        }
        $apiVersionSummary[$apiVersion] += $file.Name
    }
    
    # Show unique API versions in this file
    $uniqueVersions = $fileApiVersions | Sort-Object -Unique
    foreach ($version in $uniqueVersions) {
        $count = ($fileApiVersions | Where-Object { $_ -eq $version }).Count
        $status = if ($version -match "^201[0-9]") { "❌ LEGACY" } elseif ($version -match "^202[0-3]") { "✅ MODERN" } else { "⚠️ UNKNOWN" }
        Write-Host "  $version ($count times) $status" -ForegroundColor $(if ($status -match "LEGACY") { "Red" } elseif ($status -match "MODERN") { "Green" } else { "Yellow" })
    }
    
    # Check for inconsistencies within the file
    if ($uniqueVersions.Count -gt 1) {
        $inconsistencies += [PSCustomObject]@{
            File        = $file.Name
            ApiVersions = $uniqueVersions -join ", "
            Issue       = "Multiple API versions in same file"
        }
        Write-Host "  ⚠️ INCONSISTENCY: Multiple API versions in same file!" -ForegroundColor Red
    }
}

# Global summary
Write-Host "`n📊 Global API Version Summary" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan

$sortedVersions = $apiVersionSummary.Keys | Sort-Object -Descending
foreach ($version in $sortedVersions) {
    $files = $apiVersionSummary[$version] | Sort-Object -Unique
    $status = if ($version -match "^201[0-9]") { "❌ LEGACY" } elseif ($version -match "^202[0-3]") { "✅ MODERN" } else { "⚠️ UNKNOWN" }
    Write-Host "`n$version $status" -ForegroundColor $(if ($status -match "LEGACY") { "Red" } elseif ($status -match "MODERN") { "Green" } else { "Yellow" })
    foreach ($file in $files) {
        Write-Host "  - $file" -ForegroundColor Gray
    }
}

# Recommendations
Write-Host "`n💡 Recommendations" -ForegroundColor Cyan
Write-Host "==================" -ForegroundColor Cyan

if ($inconsistencies.Count -gt 0) {
    Write-Host "`n⚠️ Files with Inconsistencies:" -ForegroundColor Red
    $inconsistencies | ForEach-Object {
        Write-Host "  $($_.File): $($_.ApiVersions)" -ForegroundColor Red
    }
}

# Check for legacy versions
$legacyVersions = $sortedVersions | Where-Object { $_ -match "^201[0-9]" }
if ($legacyVersions.Count -gt 0) {
    Write-Host "`n❌ Legacy API Versions Found:" -ForegroundColor Red
    foreach ($version in $legacyVersions) {
        $files = $apiVersionSummary[$version] | Sort-Object -Unique
        Write-Host "  $version used in: $($files -join ', ')" -ForegroundColor Red
    }
    Write-Host "`n🔧 Action Required: Update legacy API versions to modern equivalents" -ForegroundColor Yellow
}

# Recommended modern versions
Write-Host "`n✅ Recommended Modern API Versions:" -ForegroundColor Green
Write-Host "  Microsoft.Resources/deployments: 2022-09-01" -ForegroundColor Green
Write-Host "  Microsoft.Network/*: 2023-05-01" -ForegroundColor Green
Write-Host "  Microsoft.Compute/*: 2023-03-01" -ForegroundColor Green
Write-Host "  Microsoft.Storage/*: 2023-01-01" -ForegroundColor Green

Write-Host "`n🎯 Summary:" -ForegroundColor Cyan
Write-Host "  Total ARM files analyzed: $($armFiles.Count)" -ForegroundColor White
Write-Host "  Unique API versions found: $($sortedVersions.Count)" -ForegroundColor White
Write-Host "  Files with inconsistencies: $($inconsistencies.Count)" -ForegroundColor $(if ($inconsistencies.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Legacy versions found: $($legacyVersions.Count)" -ForegroundColor $(if ($legacyVersions.Count -gt 0) { "Red" } else { "Green" })
