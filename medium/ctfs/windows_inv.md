# Investigating Windows

## Finding the Version

- Select the **Start**  button > **Settings**  > **System**  > **About** .

## Finding User Info

- Using the command line:

```bash
net user
net user John
```

We are administrators so we can use

```bash
net localgroup
// See what Users are Administrators
net localgroup Administrators
```

## See Schecduled Tasks

```powershell
Get-ScheduledTask
Get-ScheduledTask - TaskPath \
Get-ScheduledTaskInfo -TaskName "check logged in"
```

or

Windows Scheduler, Control Panel -> Scheduled Tasks

We can see scheduled apps and see what apps are running

## Detecting The Malicious Tasks

We have 4 suspicious apps running

```text
check logged in
Clean file system
falsupdate22
GameOver
```

In the Windows Scheduler we can see that **Clean file system** runs

```powershell
C:\TMP\nc.ps1 -l 1248
```

## Understanding The Attack And Finding Info For The Attacker

The **Amazon Ec2 Launch** Task is running on StartUp
This program is the virus

We can also use Event Viewer to see logs and search int the security tab for
**4672 ID** to see when did Windows assign special privileges to a new logon

Back in the Task Scheduler we can see that GameOver is a task that runned
mimikatz

Finding the port that the attacker last opened I needed to read this
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/ff428140(v=ws.10)?redirectedfrom=MSDN
Navigating into log dir we find the port

Seeing the DNS records in the cmd line

```bash
ipconfig /displaydns
```

We see the domain that the attacker used to perform the DNS poisoning

Then to find the extension name of the shell uploaded we can look inside the logs
Applications and Serv -> Microsoft -> Windows -> the Windows Defender -> Operational

```json
```
