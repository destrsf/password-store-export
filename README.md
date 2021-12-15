# password store

* Let's imagine that you have two computers, one of them has a lot of passwords and
  you want to create a copy of the storage on another computer, how to do it?


### on computer 1, you need to export passwords to a file (it will be encrypted)
```./pass-importer.py -a export -f <file_name>```


* a file will be created with the name specified in -f param


### Copy the script and file to another computer, then run 
### (this computer must already have a password-store configured):
```./pass-importer.py -a import -f <file_name>```

