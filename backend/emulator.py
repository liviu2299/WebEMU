from unicorn import *
from keystone import *
from capstone import *
from enum import IntEnum
from unicorn.x86_const import *
from utils import *
from datetime import datetime

# Constants
uc_arch = UC_ARCH_X86
uc_mode = UC_MODE_64
ks_arch = KS_ARCH_X86
ks_mode = KS_MODE_64

# States
class State(IntEnum):
    RUNNING = 0
    IDLE = 1
    NOT_RUNNING = 2
    STEP = 3

class Emulator:

    pc = "EIP"
    sp = "ESP"
    flags = "EFLAGS"

    def __init__(self):
        self.name = "x86-64bit"
        self.state = State.IDLE
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

            # 64 GR
            "R8": 0,
            "R9": 0,
            "R10": 0,
            "R11": 0,
            "R12": 0,
            "R13": 0,
            "R14": 0,
            "R15": 0,

            # Flags
            "EFLAGS": 0
        }
        self.MEMORY = {
            "size": 0x100400-0x100000,
            "starting_address": 0x100000,
            "data": None
        }
        self.STACK = {
            "size": 0x100400-0x100350,
            "starting_address": 0x100350,
            "data": None
        }
        self.start_addr = self.MEMORY['starting_address']
        self.stop_now = False
        self.end_addr = 0
        self.STEP_INFO = {}
        self.editor_mapping = {}

        self.LOG = []
        self.ERROR = "None"
        self.error_line = "None"

        self.uc = self.initiate_uc()

        return

    def update(self, MEMORY = None, STACK = None, start_addr = None, stop_now = None, end_addr = None, LOG = None, editor_mapping = None):
        """
        Updates emulator parameters
        """
        if MEMORY is not None:
            self.MEMORY["starting_address"] = MEMORY["starting_address"]
            self.MEMORY["size"] = MEMORY["size"]
        if STACK is not None:
            self.STACK["starting_address"] = STACK["starting_address"]
            self.STACK["size"] = STACK["size"]
        if start_addr is not None:
            self.start_addr = start_addr      
        if stop_now is not None:
            self.stop_now = stop_now
        if end_addr is not None:
            self.end_addr = end_addr
        if LOG is not None:
            self.LOG = LOG     
        if editor_mapping is not None:
            self.editor_mapping = editor_mapping  

        return
    
    def __str__(self):
        return "Emulator object - x86-64bit"

    def logger(self, msg: str):
        """
        Updates the log
        """
        now = datetime.now().strftime("%H:%M:%S")
        self.LOG.append('[' + now + '] ' + msg)
        return

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

            uc.mem_map(self.MEMORY["starting_address"], 2 * 1024 * 1024) # 0x200 000
            
            # Hooks
            uc.hook_add(UC_HOOK_CODE, self.hook_code)
            uc.hook_add(UC_HOOK_BLOCK, self.hook_block)
            uc.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_access)
            uc.hook_add(UC_HOOK_MEM_READ, self.hook_mem_access)
            uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid_write)
            uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self.hook_mem_invalid_read)

            uc.reg_write(unicorn.x86_const.UC_X86_REG_RSP, self.STACK["starting_address"] + self.STACK["size"])
            uc.reg_write(unicorn.x86_const.UC_X86_REG_RBP, self.STACK["starting_address"])

            uc.reg_write(unicorn.x86_const.UC_X86_REG_DS, 0x11)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_ES, 0x19)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_CS, 0x43)
            uc.reg_write(unicorn.x86_const.UC_X86_REG_SS, 0x51)

            self.start_addr = self.MEMORY['starting_address']

        except UcError as e:
            print("ERROR: %s" % e)
            self.ERROR = str(e)
            self.logger("COMPILER ERROR: %s" % e)

        return uc

    def update_uc_parameters(self, options):
        """
        Updates memory structure
        """
        self.stop()

        self.MEMORY["size"] = options['options']['MEMORY']['size']
        self.STACK["starting_address"] = options['options']['STACK']['starting_address']
        self.STACK["size"] = options['options']['STACK']['size']

        self.uc = self.initiate_uc()

        return

    def get_regs(self):
        """
        Populates the Emulator Registers
        """       
        for i in self.REGISTERS.keys():
            reg_value = self.get_reg_value(i)
            self.REGISTERS[i] = reg_value

        return True

    def get_memory(self):
        """
        Populates the Emulator Memory
        """
        try:
            mem = self.uc.mem_read(self.MEMORY["starting_address"], self.MEMORY["size"])
            stack = self.uc.mem_read(self.STACK["starting_address"], self.STACK["size"])
        
        except UcError as e:
            print("ERROR: %s" % e)
            self.ERROR = str(e)
            self.logger("COMPILER ERROR: %s" % e)
        
        mem_list = list(mem)
        stack_list = list(stack)

        self.MEMORY["data"] = [{(hex(self.MEMORY["starting_address"] + i)): mem_list[i]} for i in range(self.MEMORY["size"])]
        self.STACK["data"] = [{(hex(self.STACK["starting_address"] + i)): stack_list[i]} for i in range(self.STACK["size"])]

        return

    def update_data(self):
        """
        Updates internal data from the UC
        """
        if self.ERROR == "None":
            self.get_regs()
            self.get_memory()
            return True

        return False

    def assemble(self, code: list):
        """
        Assembles input code
        """
        code = parse_comments(code)
        formated_code = ";".join(code)
        binary_code = formated_code.encode("utf-8")

        try:
            ks = Ks(ks_arch, ks_mode)
            encoding, count = ks.asm(binary_code)
            self.end_addr = self.MEMORY["starting_address"] + len(encoding)

        except KsError as e:
            self.ERROR = str(e)
            self.logger("ASSEMBLER ERROR: %s" % e)

            # Iterative assembling till failure for error-line detection
            for i in range(len(code)):
                formated_code = ";".join(code[0:i+1])
                binary_code = formated_code.encode("utf-8")
                try:
                    partial_assembly = ks.asm(binary_code)
                except KsError as e:
                    self.error_line = i
                    break

            return (False, 0)

        # Dissasembling for cmp
        disassemble = self.disassemble(encoding)
        self.editor_mapping = line_addr_mapping(code,disassemble)

        if not encoding:
            self.ERROR = "No code to ASSEMBLE"
            self.logger('>>> No code to ASSEMBLE')
            return (False, 0)
        else:
            self.logger(">>> Code Assembled Successfully")

        print(encoding)
        return (encoding, count)
    
    def assemble_instruction(self, code):
        """
        Assembles one instruction
        """
        binary_code = code.encode("utf-8")

        try:
            ks = Ks(ks_arch, ks_mode)
            encoding, count = ks.asm(binary_code)

        except KsError as e:
            print("ERROR: %s" % e)
            self.ERROR = str(e)
            self.logger("ASSEMBLER ERROR: %s" % e)
            return False
        
        return encoding

    def disassemble_instruction(self, code, addr):
        """
        Return dissasembled string instruction
        """
        try:
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            instr = cs.disasm(bytes(code),addr)

        except CsError as e:
            print("ERROR: %s" % e)
            self.ERROR = str(e)
            self.logger("DISSASEMBLER ERROR: %s" % e)
            return False
        
        for i in instr:
            return i

    def disassemble(self, assembled_code):
        """
        Return dissasembled instructions
        """
        try:
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            disassembled = []
            for (address, size, mnemonic, op_str) in cs.disasm_lite(bytes(assembled_code), self.MEMORY["starting_address"]):
                disassembled.append({
                    "addr": address,
                    "instr": mnemonic
                })

        except CsError as e:
            print("ERROR: %s" % e)
            self.ERROR = str(e)
            self.logger("DISSASEMBLER ERROR: %s" % e)
            return False

        return disassembled   

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
            self.ERROR = str(e)
            self.logger("COMPILER ERROR: %s" % e)

        return True

    def compile(self, code: list):
        """
        Compiling and mapping of the assembled code
        """
        self.state = State.RUNNING

        encoding, count = self.assemble(code)
        if encoding != False:
            self.map_encoding(encoding)
        else:
            return False
        
        self.state = State.IDLE

        return True

    def run(self, code: list):
        """
        Runs the emulation
        """
        self.state = State.RUNNING

        encoding, count = self.assemble(code)
        if encoding != False:
            self.map_encoding(encoding)
        else:
            return False

        try:
            self.uc.emu_start(self.MEMORY["starting_address"], self.MEMORY["starting_address"] + len(encoding))
        
        except UcError as e:
            print("ERROR: %s" % e)
            self.ERROR = str(e)
            self.logger("COMPILER ERROR: %s" % e)
            return False

        self.state = State.IDLE

        return True

    def step(self):
        self.state = State.STEP
        self.stop_now = False

        if(self.get_reg_value("RIP") == self.end_addr):
            self.state = State.IDLE
            return

        try:
            self.uc.emu_start(self.start_addr, self.end_addr)
        
        except UcError as e:
            print("ERROR: %s" % e)
            self.ERROR = str(e)
            self.logger("COMPILER ERROR: %s" % e)
            return False

        return

    def stop(self):
        """
        Stops the emulation
        """
        self.state = State.NOT_RUNNING

        self.uc.emu_stop()

        return

    # Debugging / Hooks

    def hook_code(self, uc, address, size, user_data):
        """
        Hook for every instruction
        """
        
        if self.get_reg_value('RBP') >= self.get_reg_value('RSP'):
            self.logger('>>> STACK OVERFLOW')
            self.uc.emu_stop()
            return

        if self.stop_now:
            self.start_addr = self.get_reg_value("RIP")
            self.uc.emu_stop()
            return

        code = self.uc.mem_read(address, size)
        instruction = self.disassemble_instruction(code, address)

        self.logger('>>> Executing instruction [%s %s] at 0x%x, instruction size = 0x%x' % (instruction.mnemonic,instruction.op_str,address,size))
        if self.state == State.STEP:
            self.STEP_INFO = {
                "address": hex(address),
                "size": hex(size)
            }
            self.stop_now = True

        return

    def hook_block(self, uc, address, size, user_data):
        """
        Hook for every block
        """
        msg = '>>> Entering block at 0x%x' % (address)
        if self.LOG[-1] == msg:
            return

        self.logger(msg)

        return

    def hook_mem_access(self, uc, access, address, size, value, user_data):
        """
        Hook for memory access
        """
        if access == UC_MEM_WRITE:
            self.logger(">>> Write: *%#x = %#x (size = %u)"% (address, value, size))
        elif access == UC_MEM_READ:
            self.logger(">>> Read: *%#x (size = %u)" % (address, size))
        return
    
    def hook_syscall(self, uc, address, size, user_data):
        """
        Hook for syscall
        """
        self.logger('>>> Syscall')
        return

    def hook_interrupt(self, uc, no, data):
        """
        Hook for interruptions
        """
        self.logger(">>> Interrupt: %x" % (no))
        return

    def hook_mem_invalid_write(self, uc, access, address, size, value, user_data):

        self.logger(">>> Invalid memory write at 0x%x, data size = %u" % (address, size))
        return False

    def hook_mem_invalid_read(self, uc, access, address, size, value, user_data):

        self.logger(">>> Invalid memory read at 0x%x, data size = %u" % (address, size))
        return False