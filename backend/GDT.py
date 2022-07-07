from unicorn import *
from unicorn.x86_const import *
from struct import pack

# Constants
F_GRANULARITY = 0x8
F_PROT_32 = 0x4
F_LONG = 0x2
F_AVAILABLE = 0x1 

A_PRESENT = 0x80

A_PRIV_3 = 0x60
A_PRIV_2 = 0x40
A_PRIV_1 = 0x20
A_PRIV_0 = 0x0

A_CODE = 0x18
A_DATA = 0x10
A_TSS = 0x0
A_GATE = 0x0

A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2

A_DIRECTION_UP = 0x0
A_DIRECTION_DOWN = 0x4
A_CONFORMING = 0x0

S_GDT = 0x0
S_LDT = 0x4
S_PRIV_3 = 0x3
S_PRIV_2 = 0x2
S_PRIV_1 = 0x1
S_PRIV_0 = 0x0

# Dimensions

GDT_ADDR = 0x3000
GDT_LIMIT = 0x1000
GDT_ENTRY_SIZE = 0x8

CODE_ADDR = 0x100000
CODE_SIZE = 0x400

DS_SEGMENT_ADDR  = 0x7000
DS_SEGMENT_SIZE  = 0x1000

class GDT:
  def __init__(self,uc):
    self.uc = uc

  def create_selector(self,idx, flags):
    to_ret = flags
    to_ret |= idx << 3
    return to_ret

  def create_gdt_entry(self, base, limit, access, flags):
    to_ret = limit & 0xffff;
    to_ret |= (base & 0xffffff) << 16;
    to_ret |= (access & 0xff) << 40;
    to_ret |= ((limit >> 16) & 0xf) << 48;
    to_ret |= (flags & 0xff) << 52;
    to_ret |= ((base >> 24) & 0xff) << 56;
    return pack('Q',to_ret)

  def write_gdt(uc, gdt, mem):
    for idx, value in enumerate(gdt):
        offset = idx * GDT_ENTRY_SIZE
        uc.mem_write(mem + offset, value)  
    
  