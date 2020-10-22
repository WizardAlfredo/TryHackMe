# OWASP-Juice-Shop

## Open for business

Some topings that will be covered are

- [Injection](https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html)
- [Broken Authentication](https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html)
- [Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html)
- [Broken Access Control](https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html)
- [XSS](https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html)

## Recon

A good practice when testing for a web app is starting Burp
and logining the traffic of the site.  
This might be usefull later on

Looking through some reviews we can find the admin's email
**admin@juice-sh.op**

Trying to search some stuff reveales as the parameter **q**

## Injection

There are different kinds of Injection

- SQL Injection
- Command Injection
- Email Injection

1. SQL Injection is when an attacker enter a malicious query to either retrieve
data from a database. And in some cases, log into accounts

2. Command Injection is when web apps take input or user-controlled data
and run them as system commands. An attacker may tamper with this data
to execute their own system commands. This can be seen in apps that
perform misconfigured ping tests.

3. Email Injection is a security vulnerability that allows malicious users
to send email mesaages without prior authorization by the email server.
These occur when the attacker adds extra data to fields, which are not
interpreted by the server correctly

In this example tho we be using SQL Injection

We will change the email to: `' or 1=1--` and forward it to the server.

Why does this work?

1. The character `'` will close the brackets in the SQL query
2. `'OR'` in a SQL statement will return true if either side of it is true.
As `1=1` is always true, the whole statement is true.
Thus it will tell the server that the email is valid,
and log us into user id 0,
which happens to be the administrator account.
3. The ``--`` character is used in SQL to comment out data,
any restrictions on the login will no longer work as
they are interpreted as a comment.
This is like the # and // comment in python and javascript respectively.

To login to bender: `bender@juice-sh.op'--`

## Broken Authentication

In this task, we will look at exploiting authentication through different flaws.
When talking about flaws within authentication,
we include mechanisms that are vulnerable to manipulation.
These mechanisms, listed below, are what we will be exploiting.

- Weak passwords in high privileged accounts

- Forgotten password pages

In juice-shop we can exploit this vulnerability by **brute forcing the passwd**
of the admin

With Intruder and seclist we can set up the attack and find that the
passwd is: **admin123**

Another thing that we can exploit is the **passwd forgot** feature

Jim has a security question that needs to be answered in order to reset his
passwd. If we remember from the first challenge tho we know that Jim has
something to do with Star Trek. *Jim's eldest siblings middle name is*:
**George Samuel Kirk**

## Sensitive Data Exposure

A web application should store and transmit sensitive data safely and securely.
But in some cases, the developer may not correctly protect their sensitive data,
making it vulnerable.

Most of the time,
data protection is not applied consistently across the web application making
certain pages accessible to the public.
Other times information is leaked to the public without the knowledge of the
developer, making the web application vulnerable to an attack.

In our case we can exploit this by navigating to about us and through
Burp viewing the URL when we press to see the **terms of use**

We can see that the file is downloaded from `/ftp/legal.md`
This means that we have a subdir called /ftp/ and welp we can navigate
to it... awesome.

If we try to download package.json.bak tho we get a 401 response

This can be bypassed with **Poison Null Byte**

A Poison Null Byte looks like this: `%00`.
Note that we can download it using the url,
so we will encode this into a url encoded format.

The Poison Null Byte will now look like this: `%2500`.
Adding this and then a .md will bypass the 403 error!
So the URL wil going to be `/ftp/package.json.bak%2500.md`

How does this work?

A Poison Null Byte is actually a NULL terminator.
By placing a NULL character in the string at a certain byte,
the string will tell the server to terminate at that point,
nulling the rest of the string.

## Broken Access Control

Modern-day systems will allow for multiple users to have access to different pages.
Administrators most commonly use an administration page to edit,
add and remove different elements of a website.
You might use these when you are building a website with programs such as
Weebly or Wix.  

When Broken Access Control exploits or bugs are found,
it will be categorised into one of two types:

|Type                               |Description
|---                                |---
|Horizontal Privilege Escalation    |Occurs when a user can perform an action or access data of another user with the same level of permissions.
|Vertical Privilege Escalation      |Occurs when a user can perform an action or access data of another user with a higher level of permissions.

To exploit this in juice-shop we will first try to **access the admin page**.
We can do that by going on the debuger in firefox -> main-es2015 -> search admin

We find a path: `/administrator`

A good way to stop users from accessing this is to only
load parts of the application that need to be used by them.
This stops sensitive information from been leaked.  

One more thing we can do, is to **view another user's basket**
As an admin, I can click "Your Basket" and change in Burp
the get request from /rest/basket/1 to /rest/basket/2 and view the basket
of the user with UserID = 2

Lastly we can **remove all 5-star reviews**
by navigating to /administration and deleting them

## XSS

XSS or Cross-site scripting is a vulnerability that allows attackers to
run javascript in web applications.
These are one of the most found bugs in web applications.
Their complexity ranges from easy to extremely hard,
as each web application parses the queries in a different way.

There are three major types of XSS attacks:

- DOM (Special)
- Persistent (Server-side)
- Reflected (Client-side)

1. **DOM XSS** (Document Object Model-based Cross-site Scripting)
uses the HTML environment to execute malicious javascript.
This type of attack commonly uses the `<script></script>` HTML tag.

2. **Persistent XSS** is javascript that is run when the server loads the
page containing it.
These can occur when the server does not sanitise the user data when it is
uploaded to a page. These are commonly found on blog posts.

3. **Reflected XSS** is javascript that is run on
the client-side end of the web application.
These are most commonly found when the server doesn't sanitise search data.

To perform a **DOM XSS** we can use `<iframe src="javascript:alert(`xss`)">` in

This type of XSS is also called XFS (Cross-Frame Scripting),
is one of the most common forms of detecting XSS within web applications.

Websites that allow the user to modify the iframe will most likely be vulnerable
to XSS.

To perform a **Persistent XSS**
we can navigate to privacy&security -> last login ip

As it logs the 'last' login IP we will now logout so that it logs the 'new' IP.
Make sure that Burp intercept is on, so it will catch the logout request.

We will then head over to the Headers tab where we will add a new header:
True-Client-IP: `<iframe src="javascript:alert(`xss`)">`

Then forward the request to the server!
When signing back into the admin account and navigating to the Last Login IP
page again, we will see the XSS alert!

To perform a **Reflected XSS**
admin -> Order History -> Track

and instead of `track-result?id=5267-b9c643f462705301` in the URL
we will replace it with `track-result?id=<iframe src="javascript:alert(`xss`)">`
