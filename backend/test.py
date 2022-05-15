from emulator import Emulator

emu = Emulator()

code = []
code.append(".text:")
code.append("mov eax, 3")
code.append("push rax")
print(code)

emu.run(code)
emu.update_data()

print(emu.REGISTERS)


