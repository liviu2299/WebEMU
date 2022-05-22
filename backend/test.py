from emulator import Emulator

emu = Emulator()

code = []
code.append("mov rax, 3")
code.append("mov rbx, 4")
code.append("mov rcx, 5")

print(code)



print(emu.state)



