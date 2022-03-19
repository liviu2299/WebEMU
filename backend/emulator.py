from unicorn import *
from keystone import *
from typing import List

from memory import Memory

# Constants
uc_arch = UC_ARCH_X86
uc_mode = UC_MODE_64
ks_arch = KS_ARCH_X86
ks_mode = KS_MODE_64

class Emulator:

    pc = "EIP"
    sp = "ESP"
    flags = "EFLAGS"

    def __init__(self):
        self.name = "x86-64bit"
        self.state = None
        self.REGISTERS = {
            # General
            "RAX": 0,
            "RBX": 0,
            "RCX": 0,
            "RDX": 0,

            "AX": 0,
            "BX": 0,
            "CX": 0,
            "DX": 0,

            "AH": 0,
            "BH": 0,
            "CH": 0,
            "DH": 0,

            "AL": 0,
            "BL": 0,
            "CL": 0,
            "DL": 0,

            # Index & Pointers
            "RSI": 0,
            "RDI": 0,

            "RBP": 0,
            "RSP": 0,   # sp

            "RIP": 0,   # pc

            # PGR Registers
            "CS": 0,
            "DS": 0,
            "ES": 0,
            "FS": 0,
            "SS": 0,
            "GS": 0,

            # Flags
            "EFLAGS": 0
        }
        self.MEMORY = {
            "size": 0,
            "starting_address": 0x1000000,
            "data": None
        }
        self.STACK = {
            "size": 0,
            "starting_address": 0x1150000,
            "ending_address": 0x1200000,
            "data": None
        }
        self.uc = self.initiate_uc()

        return
    
    def __str__(self):
        return "Emulator object - x86-64bit"

    def get_reg_opcode(self, reg: str):
        """
        Returns the opCode of a register
        """
        return getattr(unicorn.x86_const, "UC_X86_REG_%s"%reg.upper())

    def get_reg_value(self, reg: str) -> int:
        """
        Returns integer value of a register
        """
        opcode = self.get_reg_opcode(reg)

        return self.uc.reg_read(opcode)

    def initiate_uc(self):
        """
        Initiates the compute unit
        """
        try:
            uc = unicorn.Uc(uc_arch, uc_mode)

            # TODO: Map based on .size value

            uc.mem_map(self.MEMORY["starting_address"], 2 * 1024 * 1024) # 0x200 000
            uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, self.STACK["starting_address"])
            uc.reg_write(unicorn.x86_const.UC_X86_REG_RBP, self.STACK["ending_address"])

        except UcError as e:
            print("ERROR: %s" % e)

        return uc

    def get_regs(self):
        """
        Populates the Emulator Registers
        """
        # TODO: Check the state of the emulator (Error: Cannot get reg_value before the emulation started)
        
        for i in self.REGISTERS.keys():
            reg_value = self.get_reg_value(i)
            self.REGISTERS[i] = reg_value

        return True

    def get_memory(self):
        """
        Populates the Emulator Memory
        """
        try:
            mem = self.uc.mem_read(self.MEMORY["starting_address"], 50)
        
        except UcError as e:
            print("ERROR: %s" % e)
        
        mem_list = list(mem)
        # self.MEMORY["data"] = [Memory(hex(self.MEMORY["starting_address"] + i),mem_list[i]) for i in range(50)]
        self.MEMORY["data"] = [{(hex(self.MEMORY["starting_address"] + i)): mem_list[i]} for i in range(50)]

        # TODO: Get stack memory

        return

    def update_data(self):
        """
        Updates internal data from the UC
        """
        self.get_regs()
        self.get_memory()

        return True

    def assemble(self, code: list):
        """
        Assembles input code
        """
        formated_code = ";".join(code)
        binary_code = formated_code.encode("utf-8")
        
        # TODO: Further checks on code list

        try:
            ks = Ks(ks_arch, ks_mode)
            encoding, count = ks.asm(binary_code)

        except KsError as e:
            print("ERROR: %s" % e)

        return (encoding, count)
    
    def map_encoding(self, encoding: list):
        """
        Map the encoded instructions in memory
        """

        if not encoding:
            print("No encoding to map")
            return False
        else:
            b_encoding = bytes(encoding)

        try:
            self.uc.mem_write(self.MEMORY["starting_address"], b_encoding)

        except UcError as e:
            print("ERROR: %s" % e)

        return True

    def run(self, code: list):
        """
        Runs the emulation
        """

        encoding, count = self.assemble(code)
        self.map_encoding(encoding)

        try:
            self.uc.emu_start(self.MEMORY["starting_address"], self.MEMORY["starting_address"] + len(encoding))
        
        except UcError as e:
            print("ERROR: %s" % e)
            return False

        return True

    # TODO: Sequentially computing
    def step(self):
        return

    def stop(self):
        """
        Stops the emulation
        """
        self.uc.emu_stop()

        return
    