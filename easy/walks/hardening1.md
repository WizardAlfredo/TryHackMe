# Hardening Basics Part 1

## Securing User Accounts

Managing the users of any system is no small task.
The principle of least privilege states that each user should only have enough
access to perform their daily tasks.
This means that an HR Admin should not have access to the system log files.
However, this may mean that an IT Administrator does have access to the
HR drive but not necessarily employee information.
This chapter will focus on securing your user accounts through the smart
configuration of sudo, using complex passwords,
disabling root access and locking down home directories.

### The Dangers of Root

The root user is the highest user in a Linux system.
They are able to do anything, including modifying system and boot files.
Knowing that, you can see why logging in as root is probably not ideal in most
situations.

Being on a site like this,
you probably use root to utilize the features of your Kali, Parrot,
or other hacking Operating System.
In an environment like this, it's completely fine.
But in the real world,
using root can be and should be viewed as a danger to your system and company.

There is a tool in Linux that allows users to use their standard user accounts
but still access programs and binaries as if they were root with their standard
user passwords. That tool is `sudo`.

### Sudo

#### Advantages of sudo

It was touched on above but when sudo is configured correctly,
it greatly increases the security of your Linux environment.
There are a few advantages it has such as:

1. Slowing hackers down. Since the root login will most likely be disabled and
your users are properly granted sudo,
any attacker will not know which account to go after, thus slowing them down.
If they are slowed down enough, they may stop the attack and give up
2. Allow non-privileged users to perform privileged tasks by entering their
own passwords
3. Keeps in line with the principle of least privilege by allowing administrators
to assign certain users full privileges,
while assigning other users only the privileges they need to complete
their daily tasks

#### Adding Users to a Predefined Admin Group

##### Method 1

This is the first way to add users to the sudo group.
Generally, this is considered the easiest method to allow users to use the sudo command.
On Ubuntu 18.04, unless otherwise specified upon account creation,
the user is automatically added to the sudo group.
Let's take a look at nick's groups with the `groups` command.

We can see that Nick is a part of the sudo group (as well as a few others).
If Nick was not part of the sudo group already,
we could easily add him with one simple command: `usermod -aG sudo nick`.
The `-aG` options here will **add** Nick to the **group** sudo.
Using the -a option helps Nick retain any previously existing groups.
You can also directly add a user to the sudo group upon creation with the command,
`useradd -G sudo james`.

But what does adding a user to the sudo group in Ubuntu mean?
By default, Ubuntu allows sudo users to execute any program as root with their password.
There are a few ways we can check this information.
The first way is as Nick with `sudo -l`.

The important information are in the last lines.
This is saying that Nick (as part of the sudo group) may run all commands
as any user on any machine.

There's another way to view this information and that's with `visudo`.
This opens the sudo policy file.
The sudo policy file is stored in `/etc/sudoers`.
We can do it here as Nick,
but we would need to use sudo if we want to edit it since it can only be edited
by the root user (using just `visudo` as Nick actually gives a permission denied).

This gives the same information as `sudo -l` but it has one difference;
the "%sudo" indicates that it's for the group, sudo.
There are other groups in this file such as "admin".
This is where administrators can set what programs a user in a certain group
can perform and whether or not they need a password.
You may have seen sometimes `%sudo ALL=(ALL:ALL) ALL NOPASSWD: ALL`.
That NOPASSWD part says that the user that is part of the sudo group does not
need to enter their local password to use sudo privileges.
Generally, this is not recommended - even for home use.

##### Method 2

This next method utilizes the sudo policy file mentioned in Method 1.
It's nice to be able to modify what an entire group can do,
but that's just for Ubuntu.
If you're managing users in a network across multiple flavors of Linux
(CentOS, Red Hat, etc.), where the sudo group may be called something different,
this method may be more preferable.

What you can do is add a User Alias to the policy file and add users to that
alias (below), or add lines for individual users.
The first image below creates the ADMIN User Alias and assigns 3 users to it
and then says that this Alias has full sudo powers.

I would not recommend the second option (individual user aliases)
in a large network since this can become unwieldy very quickly.
The first option is going to be your best bet as you'll see in the next
Task that we can simply add users to this alias and control which commands they
have access to with sudo very easily.

#### Setting Up sudo for Only Certain Delegated Privileges

In the previous task, we saw how we can add users to the sudo group,
and set up a User Alias in the sudo policy file, visudo.

I know I've hammered this point a lot in these two tasks,
but the next method that we'll talk about here will ensure that users are
assigned to the groups they belong to and only are allowed access to the programs
they need to complete their daily tasks.
This is how sudo aligns with the principle of least privilege.

It does this by allowing the root user to set what are called Command Aliases
in the sudo policy file.
Just as we set a User Alias in this file in the last task,
we'll set a Command Alias now in the same file.
Since we've already gone over it,
I'm going to create another User Alias with the name of SYSTEMADMINS and
assign some users to it.
So again, using sudo visudo,
we'll edit the line under the comment # Cmnd alias specification

We'll just add a few commands to the list.
These don't mean anything in the actual context of what a System Admin would need.
In reality, a System Admin would probably have sudo access to most things,
but for brevity, let's only include a few.

The SYSTEM Command Alias allows the user to run systemctl restart,
systemctl restart ssh and chmod .
What do you think will happen if someone in the SYSTEMADMINS User Alias tried
to run systemctl restart apache2?
It would fail because that specific service has not been specified in the Alias.
However, they are able to restart the ssh service because this is specified.
And lastly, they can use chmod with all options.

If we wanted to allow the SYSTEMADMINS User Alias to be able to restart all services,
we can use a wildcard character at the end so the new Alias would look like
/usr/bin/systemctl restart *.

Different Ways to Assign Commands

We can also assign Command Aliases to individual users,
specific commands to individual users, and Command Aliases to groups:

So dark is assigned specifically to the WEBDEV Command Alias,
the user paradox is assigned only the cd command (poor Paradox)
and the HR User Alias can only perform tasks in the HR Command Alias.
See how useful the sudo policy can be in allowing you to separate privileges?

A Mention of Host Aliases

Host Aliases exist.
They are a way to trickle down a sudo policy across the network and different servers.
For example, you may have a MAILSERVERS Host Alias which contains servers
mail1 and mail2.
This Host Alias has certain users or groups assigned to it like we've demonstrated
in these last two tasks and that Host Alias has a Command Alias assigned to it
stating which commands those users are able to run.

When those users run a command on mail1 or mail2,
the server will check the sudo policy file to see if they can do what they're
trying to do.

I don't want to go into too much detail about it here because in a home
environment and small-medium business environments,
it probably is just easier to copy the sudo policy file to each server in the network.
This will really only come into play with large enterprise networks and even
then they will probably be using one centralized Ansible or other automation in effect.

```json
```
