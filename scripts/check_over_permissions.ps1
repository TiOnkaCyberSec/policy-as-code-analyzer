param (
    [string]$PolicyPath = "../sample_policies"
    )

 Write-Host "Scanning IAM policies for over-permission access..." -ForegroundColor Cyan 
 
 Get-ChildItem - Path $PolicyPath -Filter *.json | ForEach-Object {
    Write-Host "`nPolicy File: $($_.Name)" -ForegroundColor Yellow
    $policy = Get-Content $_.FullName | ConvertFrom-Json

    foreach ($statement in $policy.Statement) {
        if ($statement.Action -contains "*"){
            Write-Host " -Wildcard Action detected" -ForegroundColor Red
        }
        if ($statement.Resource -contains "*"){
            Write-Host " -Wildcard Resource detected" -ForegroundColor Red
        }
        foreach ($action in $statement.Action) {
            if ($action -like "*:*" -and $action.EndsWith(":*")){
                Write-Host " - Full service access: $action" -ForegroundColor DarkYellow
            }
        }
    }
 }