from unicorn import *
from keystone import *
from unicorn.x86_const import *

from memory import Memory

## 1) ASSEMBLER

code = b"""
        mov ah, 3;
        mov al, 2;
        """

try:
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)
    print(type(encoding))

except KsError as e:
    print("ERROR: %s" %e)

## 2) COMPUTE UNIT

xcode = bytes(encoding)

# memory address where emulation starts
ADDRESS = 0x1000000

try:
    # Initialize emulator in X86-32bit mode
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # map 2MB memory for this emulation
    mu.mem_map(ADDRESS, 2 * 1024 * 1024) # 0x200 000

    # write machine code to be emulated to memory
    mu.mem_write(ADDRESS, xcode)

    # initialize machine registers
    mu.reg_write(UC_X86_REG_ECX, 1)
    mu.reg_write(UC_X86_REG_EDX, 1)
    mu.reg_write(UC_X86_REG_ESP, 0x1000100)

    # emulate code in infinite time & unlimited instructions
    mu.emu_start(ADDRESS, ADDRESS + len(xcode))
    
    r_eax = mu.reg_read(UC_X86_REG_RAX)
    r_ebx = mu.reg_read(UC_X86_REG_EAX)
    r_ecx = mu.reg_read(UC_X86_REG_ECX)
    r_edx = mu.reg_read(UC_X86_REG_EDX)
    r_sp = mu.reg_read(UC_X86_REG_ESP)
    print(">>> EAX = 0x%x" %r_eax)
    print(">>> EBX = 0x%x" %r_ebx)
    print(">>> ECX = 0x%x" %r_ecx)
    print(">>> EDX = 0x%x" %r_edx)
    print(">>> SP = 0x%x" %r_sp)
    print(">>> MemoryStart = 0x%x" %ADDRESS)

    mem = mu.mem_read(0x1000000, len(xcode) + 10)
    mem_formated = list(mem)
    temp = mu.mem_read(16777217, 2)

    print(">>> Memory = ")
    print(mem_formated)

    print(hex(0x1000000 + 1))

 

    RAM = [Memory(hex(0x1000000 + i),mem_formated[i]) for i in range(10)]

    for i in RAM:
        print(i)


except UcError as e:
    print("ERROR: %s" % e)

