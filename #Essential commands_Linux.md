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
| tr '[:upper:]' '[:lower:]' : upper to lower

| cut -d '|' -f 2 : delimeter 

replacing string 
| tr ';' '\n' : ; to line-break
sed 's/unix/linux' text.txt
sed 's/\\//g'  : replace all duplications


Repeated lines/words
  need to be sorted/adjacent in alphabetical order, and then uniq 
sort comparingboth.txt | unique -d
```


### Zip
```
unzip -d newdir FILE.zip
unzip -l FILE.zip : list
```

```
tar -cf all.tar * : create 
tar -xvf archieve.tar : extract
tar -tvf archieve tar: list 
mkdir unzip&&cd unzip&&tar -xvf
```


