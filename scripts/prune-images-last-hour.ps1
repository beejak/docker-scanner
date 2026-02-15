# Remove Docker images that were created (pulled) in the last N hours.
# Use after a baseline run to free disk space. Run from repo root or any directory.
# Usage:
#   .\scripts\prune-images-last-hour.ps1           # last 1 hour (default)
#   .\scripts\prune-images-last-hour.ps1 -Hours 3 # last 3 hours

param(
    [int] $Hours = 1
)

$cutoff = (Get-Date).AddHours(-$Hours)
$toRemove = @()

docker images --format "{{.ID}} {{.CreatedAt}}" | ForEach-Object {
    if ($_ -match '^([a-f0-9]+)\s+(.+)$') {
        $id = $Matches[1]
        $createdStr = $Matches[2].Trim()
        try {
            $created = [DateTime]::Parse($createdStr)
            if ($created -ge $cutoff) {
                $toRemove += $id
            }
        } catch {
            # Skip unparseable lines
        }
    }
}

if ($toRemove.Count -eq 0) {
    Write-Host "No images found that were created in the last $Hours hour(s)."
    exit 0
}

# Deduplicate (same image ID may appear if multiple tags)
$toRemove = $toRemove | Sort-Object -Unique
Write-Host "Removing $($toRemove.Count) image(s) created in the last $Hours hour(s)..."
foreach ($id in $toRemove) {
    docker rmi -f $id 2>&1
}
Write-Host "Done."
