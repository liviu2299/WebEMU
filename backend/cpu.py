from unicorn import *
from keystone import *
from unicorn.x86_const import *

def uc(input):

    code = input.encode("utf-8")

    ## 1) Assemble
    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        encoding, count = ks.asm(code)
    except KsError as e:
        print("ERROR: %s" %e)

    ## 2) Compute

    xcode = bytes(encoding)
    ADDRESS = 0x1000000

    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, xcode)

        # initialize machine registers
        mu.reg_write(UC_X86_REG_ECX, 1)
        mu.reg_write(UC_X86_REG_EDX, 1)

        # emulate code in infinite time & unlimited instructions
        mu.emu_start(ADDRESS, ADDRESS + len(xcode))
        
        r_eax = mu.reg_read(UC_X86_REG_EAX)
        r_ebx = mu.reg_read(UC_X86_REG_EBX)
        r_ecx = mu.reg_read(UC_X86_REG_ECX)
        r_edx = mu.reg_read(UC_X86_REG_EDX)

    except UcError as e:
        print("ERROR: %s" % e)

    return {
        "A": r_eax,
        "B": r_ebx,
        "C": r_ecx,
        "D": r_edx
    }
