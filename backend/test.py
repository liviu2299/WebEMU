from emulator import Emulator

emu = Emulator()

code = []
code.append("mot eax, 3")
code.append("push eax")
print(code)

emu.run(code)
emu.update_data()

print(emu.REGISTERS)
print(type(str(emu.ERROR)))






