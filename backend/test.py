from emulator import Emulator

emu = Emulator()

code = []
code.append("mov ah, 3")
code.append("mov al, 2")
code.append("push 5")
print(code)


emu.run(code)
emu.get_regs()
emu.get_memory()

print(emu.REGISTERS)
for i in emu.MEMORY["data"]:
    print(i)




