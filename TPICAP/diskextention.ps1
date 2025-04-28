try {
    # Refreshes the storage information on the host
    Update-HostStorageCache
    
    # Get the disk number for the C: drive
    $diskNumber = (Get-Partition -DriveLetter C).DiskNumber
    
    if ($diskNumber -eq $null) {
        throw "Failed to retrieve disk number for C: drive."
    }
    
    # Get Disk object for further operations
    $disk = Get-Disk -Number $diskNumber
    
    # Get the partition object for the C: drive
    $partition = Get-Partition -DiskNumber $diskNumber | Where-Object { $_.DriveLetter -eq 'C' }
    
    if ($partition -eq $null) {
        throw "Failed to retrieve partition for C: drive."
    }

    # Get max size available for the partition
    $maxSize = $partition | Get-PartitionSupportedSize

    # Check if there is space to extend the C: drive
    if ($maxSize.SizeMax -gt $partition.Size) {
        # Perform the resize operation
        Resize-Partition -DiskNumber $diskNumber -PartitionNumber $partition.PartitionNumber -Size $maxSize.SizeMax
        Write-Output "C: drive has been extended to use all available space."
        $drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeSpace = $drive.FreeSpace / 1GB
Write-Host "Free space on C: drive: $freeSpace GB"
    } else {
        Write-Output "No additional unallocated space available to extend C: drive."
        $drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeSpace = $drive.FreeSpace / 1GB
Write-Host "Free space on C: drive: $freeSpace GB"
    }
} catch {
    Write-Error "An error occurred: $_"
}

