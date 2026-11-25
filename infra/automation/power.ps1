# Terraform publishes this file as lab-start and lab-stop with a fixed direction.
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$SchedulerClientId,
    [Parameter(Mandatory)][string]$ClusterId,
    [Parameter(Mandatory)][string]$VmId
)
$ErrorActionPreference = 'Stop'
$direction = '__LAB_DIRECTION__'
Disable-AzContextAutosave -Scope Process | Out-Null
$login = Connect-AzAccount -Identity -AccountId $SchedulerClientId -Subscription $SubscriptionId
$context = $login.Context

function Read-Resource([string]$Path) {
    $response = Invoke-AzRestMethod -Path $Path -Method GET -DefaultProfile $context
    if ($response.StatusCode -ne 200) { throw "Read returned HTTP $($response.StatusCode) on $Path" }
    return ($response.Content | ConvertFrom-Json)
}

$aksVersion = '2025-10-01'
$vmVersion = '2024-11-01'
function Read-Cluster { Read-Resource "$($ClusterId)?api-version=$aksVersion" }
function Get-VmPower {
    $view = Read-Resource "$VmId/instanceView?api-version=$vmVersion"
    $state = @($view.statuses | Where-Object { $_.code -like 'PowerState/*' })
    if ($state.Count -ne 1) { throw 'VM power state is unavailable' }
    return $state[0].code
}
function Send-Action([string]$Path) {
    $response = Invoke-AzRestMethod -Method POST -Path $Path -DefaultProfile $context
    if ($response.StatusCode -notin @(200, 202, 204)) { throw "Action returned HTTP $($response.StatusCode) on $Path" }
}
function Wait-For([scriptblock]$Condition, [string]$Description) {
    $until = (Get-Date).AddMinutes(30)
    do {
        if (& $Condition) { return }
        Start-Sleep -Seconds 15
    } while ((Get-Date) -lt $until)
    throw "Timed out waiting for $Description"
}
function Set-ClusterPower([string]$Target, [string]$Action) {
    $current = Read-Cluster
    if ($current.properties.provisioningState -ne 'Succeeded') { throw 'AKS changed state during the job' }
    if ($current.properties.powerState.code -eq $Target) { return }
    Send-Action "$ClusterId/$($Action)?api-version=$aksVersion"
    Wait-For {
        $cluster = Read-Cluster
        if ($cluster.properties.provisioningState -in @('Failed','Canceled')) { throw 'AKS power operation failed' }
        $cluster.properties.powerState.code -eq $Target -and $cluster.properties.provisioningState -eq 'Succeeded'
    } "AKS $Target"
}
function Set-VmPower([string]$Target, [string]$Action) {
    $state = Get-VmPower
    if ($state -eq $Target) { return }
    if ($state -notin @('PowerState/running','PowerState/stopped','PowerState/deallocated')) {
        throw "VM already has a power operation in progress ($state)"
    }
    Send-Action "$VmId/$($Action)?api-version=$vmVersion"
    Wait-For { (Get-VmPower) -eq $Target } "VM $Target"
}

$cluster = Read-Cluster
if ($cluster.properties.provisioningState -in @('Failed','Canceled')) { throw 'AKS needs operator attention' }
if ($cluster.properties.provisioningState -ne 'Succeeded') {
    Write-Output 'Skipped both resources because an AKS operation is in progress'
    return
}
if ($direction -eq 'start') {
    Set-VmPower 'PowerState/running' 'start'
    Set-ClusterPower 'Running' 'start'
} elseif ($direction -eq 'stop') {
    if ($cluster.tags.'lab-keep-running' -eq 'true') {
        Write-Output 'Keeping AKS and its database available for the tagged session'
        return
    }
    Set-ClusterPower 'Stopped' 'stop'
    $vm = Read-Resource "$($VmId)?api-version=$vmVersion"
    if ($vm.tags.'lab-keep-running' -ne 'true') { Set-VmPower 'PowerState/deallocated' 'deallocate' }
} else {
    throw 'Unknown runbook direction'
}
Write-Output "Completed lab-$direction"
