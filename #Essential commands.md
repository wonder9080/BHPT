# Essential commands

### CLI
```
sudo -i : to root
sudo -l : 
su USER : to USER
COMMAND -h | less
```

### kali based
```
sudo apt search impacket : up-to-date check
sudo apt list | grep -i impacket : installed or upgradable check 
```

### editor
```
vi
nano
editor
mousepad
```

### find something
```
locate
which vi
find / -name NAME 2>/dev/null
```

### edit string 
```
| tr -d "'" : ' except
| tr ';' '\n' : ; to line-break

| cut -d '|' -f 2 : delimeter 
```



```
tar -cf all.tar * : create 
tar -xvf archieve.tar : extract
tar -tvf archieve tar: list 
mkdir unzip&&cd unzip&&tar -xvf
```

## Windows
- in powershell, 
```
ls -Force : hidden file
```

### Zip
```
unzip -d newdir FILE.zip
unzip -l FILE.zip : list
```
### Linux Enumeration
```
hostnamectl : hostname + uname -a 
```

