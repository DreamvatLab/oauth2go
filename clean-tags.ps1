# Get all git tags
$allTags = git tag

# Filter tags matching the format vX.X.X
$versionTags = $allTags | Where-Object { $_ -match '^v\d+\.\d+\.\d+$' }

if ($versionTags.Count -eq 0) {
    Write-Host "No tags found matching the format vX.X.X." -ForegroundColor Yellow
    exit
}

# Convert tags to version objects for comparison
$versions = $versionTags | ForEach-Object {
    [PSCustomObject]@{
        Tag = $_
        Version = [Version]($_ -replace '^v', '')
    }
}

# Find the latest version
$latest = $versions | Sort-Object Version -Descending | Select-Object -First 1

Write-Host "Keeping the latest version tag: $($latest.Tag)" -ForegroundColor Green

# Determine tags to delete
$toDelete = $versions | Where-Object { $_.Tag -ne $latest.Tag }

# Delete local tags
$toDelete | ForEach-Object {
    git tag -d $_.Tag
}

# Delete remote tags
$toDelete | ForEach-Object {
    git push origin ":refs/tags/$($_.Tag)"
}

Write-Host "All other tags have been deleted (locally and remotely)." -ForegroundColor Cyan
