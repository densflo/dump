Connect-VIServer -Server LD5PINFVCA01 -User corp\srvcDev42VC -Password "R#2TwaM@"

foreach($vc in $global:DefaultVIServers){

    foreach($cluster in Get-Cluster -Server $vc){

        foreach($esx in Get-VMHost -Location $cluster -Server $vc){

            foreach($vm in Get-VM -Location $esx -Server $vc){

                foreach($hd in Get-HardDisk -VM $vm -Server $vc){

                    $obj = [ordered]@{

                        vCenter = $vc.Name

                        Cluster = $cluster.name

                        VMHost = $esx.Name

                        VMHostRamGB= $esx.MemoryTotalGB

                        VMHostCpu = $esx.NumCpu

                        VM = $vm.Name

                        VMRamGB = $vm.MemoryGB

                        VmCpu = $vm.NumCpu

                        Disk = $hd.Name

                        DiskGB = $hd.CapacityGB

                    }

                    New-Object PSObject -Property $obj

                }

            }

        }

    }

}

Script #2
foreach($vc in $global:DefaultVIServers){

    foreach($dsc in Get-DatastoreCluster -Server $vc){

        foreach($ds in Get-Datastore -Location $dsc -Server $vc){

            foreach($vm in Get-VM -Datastore $ds -Server $vc){

                foreach($hd in Get-HardDisk -VM $vm -Server $vc){

                    $obj = [ordered]@{

                        vCenter = $vc.Name

                        DatastoreCluster = $dsc.name

                        Datastore = $ds.Name

                        CapacityGB = $ds.CapacityGB

                        UsedGB = $ds.CapacityGB - $ds.FreeSpaceGB

                        VM = $vm.Name

                        VMRamGB = $vm.MemoryGB

                        VmCpu = $vm.NumCpu

                        Disk = $hd.Name

                        DiskGB = $hd.CapacityGB

                    }

                    New-Object PSObject -Property $obj

                }

            }

        }

    }

}

