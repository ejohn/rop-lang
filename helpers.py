import struct
from subprocess import Popen, PIPE, STDOUT
import re

def pack(addr):
    return struct.pack('<I', addr)


def pack_signed(addr):
    return struct.pack('<i', addr)


def unpack(addr):
    return struct.unpack('<I', addr)


def gen_mask(count, direction="right"):
    mask = "0"*count + "1" * (32-count)

    if direction == "left":
        mask = mask[::-1]

    return int(mask,2)


## Hacky!
def fix_offsets():
    libc_printf_offset_cmd = Popen("gdb -batch -x offsets/libc_printf.gdb libc.so.6",	
				shell=True, stdout=PIPE, stderr=STDOUT, bufsize=1024).stdout
    libc_printf_offset_stdout = libc_printf_offset_cmd.readlines()

    libc_printf_offset = re.match("\$1 = {<text variable, no debug info>} (.*) <printf>\\n", 
            libc_printf_offset_stdout[0]).group(1)

    vuln_printf_offset_cmd = Popen("gdb -batch -x offsets/vuln_printf.gdb vuln",
				shell=True, stdout=PIPE, stderr=STDOUT, bufsize=1024).stdout
    vuln_printf_offset_stdout = vuln_printf_offset_cmd.readlines()
    vuln_printf_offset = re.match("\$1 = {<text variable, no debug info>} (.*) <printf>\\n", 
            vuln_printf_offset_stdout[3]).group(1)

    readelf_vuln_bss_cmd = Popen("readelf -S vuln | grep bss",
				shell=True, stdout=PIPE, stderr=STDOUT, bufsize=1024).stdout
    readelf_vuln_bss_stdout = readelf_vuln_bss_cmd.readlines()
    readelf_vuln_bss_addr = readelf_vuln_bss_stdout[0].split(' ')[27]

    return int(vuln_printf_offset, 16) - int(libc_printf_offset, 16), int(readelf_vuln_bss_addr, 16)




