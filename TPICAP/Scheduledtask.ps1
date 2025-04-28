# Get all scheduled tasks in the root \ location
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -eq '\' }

# Loop through each task and display the details
foreach ($task in $tasks) {
    $taskName = $task.TaskName
    $lastRunTime = if ($task.LastRunTime) {$task.LastRunTime.ToString('HH:mm:ss')} else {"Never"}
    $nextRunTime = if ($task.NextRunTime) {$task.NextRunTime.ToString('HH:mm:ss')} else {"Not Scheduled"}
    $taskPath = $task.TaskPath
    $state = $task.State

    # Get the task triggers
    $triggers = (Get-ScheduledTask -TaskName $task.TaskName).Triggers | ForEach-Object {
        if ($_.Repetition) {
"Every $($_.Repetition.Interval.ToString()) for $($_.Repetition.Duration.ToString())"
        }
        elseif ($_.Schedule) {
            if ($_.Schedule.Daily) {
                "Daily at $($_.Schedule.Daily.Time.ToString('HH:mm:ss'))"
            }
            elseif ($_.Schedule.Weekly) {
                 "Weekly on $($_.Schedule.Weekly.DaysOfWeek -join ', ') at $($_.Schedule.Weekly.Time.ToString('HH:mm:ss'))"
            }
            elseif ($_.Schedule.Monthly) {
                "Monthly on day $($_.Schedule.Monthly.DaysOfMonth -join ', ') at $($_.Schedule.Monthly.Time.ToString('HH:mm:ss'))"
            }
             else {
                "Scheduled"
            }
        }
         elseif ($_.AtLogOn) {
            "At Logon"
        }
        elseif ($_.AtStartup) {
            "At Startup"
        }
        elseif ($_.Once) {
            "Once at $($_.StartBoundary.ToString('HH:mm:ss'))"
        }
else {
    "Unknown Trigger Type: $($_.GetType().Name)"
}
    }
    $triggerInfo = if ($triggers) { $triggers -join ", " } else { "No trigger" }

    Write-Host "Task Name: $taskName"
    Write-Host "  Last Run Time: $lastRunTime"
    Write-Host "  Next Run Time: $nextRunTime"
    Write-Host "  Task Path: $taskPath"
    Write-Host "  State: $state"
    Write-Host "  Trigger: $triggerInfo"
    Write-Host "----------------------------------------"
}

# Select the properties you want to export, formatting LastRunTime to show only the time
$taskDetails = $tasks | Select-Object TaskName, @{Name='LastRunTime';Expression={$_.LastRunTime.ToString('HH:mm:ss')}}, NextRunTime, TaskPath, State, @{Name='Trigger';Expression={$_.Triggers | ForEach-Object {if ($_.Repetition) {"Every $($_.Repetition.Interval) $($_.Repetition.IntervalUnit) $($_.Repetition.Duration)"} elseif ($_.Schedule) {$_.Schedule} elseif ($_.AtLogOn) {"At Logon"} elseif ($_.AtStartup) {"At Startup"} else {"Unknown"}} -join ", "}}

# Export the details to a CSV file
$taskDetails | Export-Csv -Path "TaskSchedules.csv" -NoTypeInformation
