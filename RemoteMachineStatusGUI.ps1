Add-Type -AssemblyName System.Windows.Forms

# Create form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Remote Machine Status"
$form.Size = New-Object System.Drawing.Size(400,300)
$form.StartPosition = "CenterScreen"

# Machine Name Label and TextBox
$machineLabel = New-Object System.Windows.Forms.Label
$machineLabel.Location = New-Object System.Drawing.Point(10,20)
$machineLabel.Size = New-Object System.Drawing.Size(100,20)
$machineLabel.Text = "Machine Name/IP:"
$form.Controls.Add($machineLabel)

$machineTextBox = New-Object System.Windows.Forms.TextBox
$machineTextBox.Location = New-Object System.Drawing.Point(120,20)
$machineTextBox.Size = New-Object System.Drawing.Size(250,20)
$form.Controls.Add($machineTextBox)

# Username Label and TextBox
$userLabel = New-Object System.Windows.Forms.Label
$userLabel.Location = New-Object System.Drawing.Point(10,50)
$userLabel.Size = New-Object System.Drawing.Size(100,20)
$userLabel.Text = "Username:"
$form.Controls.Add($userLabel)

$userTextBox = New-Object System.Windows.Forms.TextBox
$userTextBox.Location = New-Object System.Drawing.Point(120,50)
$userTextBox.Size = New-Object System.Drawing.Size(250,20)
$form.Controls.Add($userTextBox)

# Password Label and TextBox
$passLabel = New-Object System.Windows.Forms.Label
$passLabel.Location = New-Object System.Drawing.Point(10,80)
$passLabel.Size = New-Object System.Drawing.Size(100,20)
$passLabel.Text = "Password:"
$form.Controls.Add($passLabel)

$passTextBox = New-Object System.Windows.Forms.TextBox
$passTextBox.Location = New-Object System.Drawing.Point(120,80)
$passTextBox.Size = New-Object System.Drawing.Size(250,20)
$passTextBox.PasswordChar = "*"
$form.Controls.Add($passTextBox)

# Status TextBox
$statusTextBox = New-Object System.Windows.Forms.TextBox
$statusTextBox.Location = New-Object System.Drawing.Point(10,120)
$statusTextBox.Size = New-Object System.Drawing.Size(360,100)
$statusTextBox.Multiline = $true
$statusTextBox.ReadOnly = $true
$statusTextBox.ScrollBars = "Vertical"
$form.Controls.Add($statusTextBox)

# Connect Button
$connectButton = New-Object System.Windows.Forms.Button
$connectButton.Location = New-Object System.Drawing.Point(150,230)
$connectButton.Size = New-Object System.Drawing.Size(100,30)
$connectButton.Text = "Connect"
$connectButton.Add_Click({
    try {
        $credential = New-Object -TypeName System.Management.Automation.PSCredential `
            -ArgumentList $userTextBox.Text, (ConvertTo-SecureString $passTextBox.Text -AsPlainText -Force)
        
        $status = Invoke-Command -ComputerName $machineTextBox.Text -Credential $credential -ScriptBlock {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $cpu = Get-CimInstance -ClassName Win32_Processor
            $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
            
            return @{
                Uptime = [math]::Round((Get-Date) - $os.LastBootUpTime).TotalHours
                CPU = $cpu.LoadPercentage
                Memory = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)
                Disk = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 2)
            }
        }
        
        $statusTextBox.Text = @"
Machine Status:
Uptime: $($status.Uptime) hours
CPU Usage: $($status.CPU)%
Memory Usage: $($status.Memory) GB
C: Drive Usage: $($status.Disk) GB
"@
    }
    catch {
        $statusTextBox.Text = "Error connecting to machine: $_"
    }
})
$form.Controls.Add($connectButton)

# Show form
$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()
