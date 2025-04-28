param (
    [string]$vmName,
    [string]$destinationDatastore,
    [string]$destinationHost,
    [string]$destinationNetwork,
    [string]$destinationVCenter
)

# Connect to source vCenter if not already connected
if (-not (Get-PowerCLIConfiguration).DefaultVIServer) {
    $sourceVCenterServer = Read-Host -Prompt 'Enter your source vCenter server address'
    $sourceVCenterCredential = Get-Credential -Message 'Enter your source vCenter credentials'
    Connect-VIServer -Server $sourceVCenterServer -Credential $sourceVCenterCredential
}

# Get the virtual machine object
$vm = Get-VM -Name $vmName

# Connect to destination vCenter
$destinationVCenterCredential = Get-Credential -Message 'Enter your destination vCenter credentials'
$destinationVCenterSession = Connect-VIServer -Server $destinationVCenter -Credential $destinationVCenterCredential

# Get the destination host, datastore, and network objects
$destinationHostObject = Get-VMHost -Name $destinationHost -Server $destinationVCenterSession
$destinationDatastoreObject = Get-Datastore -Name $destinationDatastore -Server $destinationVCenterSession
$destinationNetworkObject = Get-VirtualPortGroup -Name $destinationNetwork -Server $destinationVCenterSession

# Perform Cross-vCenter vMotion (Clone)
$relocateSpec = New-Object VMware.Vim.VirtualMachineRelocateSpec
$relocateSpec.Datastore = $destinationDatastoreObject.ExtensionData.MoRef
$relocateSpec.Host = $destinationHostObject.ExtensionData.MoRef
$relocateSpec.Pool = $destinationHostObject.Parent.ExtensionData.ResourcePool.MoRef

$networkAdapter = $vm | Get-NetworkAdapter
$relocateSpec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (1)
$relocateSpec.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
$relocateSpec.DeviceChange[0].Operation = [VMware.Vim.VirtualDeviceConfigSpecOperation]::edit
$relocateSpec.DeviceChange[0].Device = $networkAdapter.ExtensionData
$relocateSpec.DeviceChange[0].Device.Backing = New-Object VMware.Vim.VirtualEthernetCardNetworkBackingInfo
$relocateSpec.DeviceChange[0].Device.Backing.DeviceName = $destinationNetworkObject.ExtensionData.Name

$cloneSpec = New-Object VMware.Vim.VirtualMachineCloneSpec
$cloneSpec.Location = $relocateSpec
$cloneSpec.PowerOn = $false

$vm.ExtensionData.CloneVM_Task($vm.ExtensionData.Parent, $vmName + "_clone", $cloneSpec) | Out-Null
Write-Host "Cloning $vmName to $destinationHost and $destinationDatastore on $destinationVCenter..."

# Wait for the task to complete
$task = Get-Task -Server $destinationVCenterSession | Where-Object { $_.Name -eq "CloneVM_Task" -and $_.DescriptionId -eq "VirtualMachine.clone" } | Sort-Object -Property StartTime -Descending | Select-Object -First 1
$task | Wait-Task
if ($task.State -eq "Success") {
    Write-Host "Clone operation completed successfully."
}
else {
    Write-Host "Clone operation failed."
}

Disconnect-VIServer -Server $destinationVCenter -Confirm:$false

