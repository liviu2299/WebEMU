from emulator import Emulator

emu = Emulator()

code = []
code.append("mov eax, 3")

print(code)

emu.run(code)
emu.update_data()

print(emu.REGISTERS)

context = emu.uc.context_save()
emu.stop()

##########

code = []
code.append("mov ebx, 2")

print(code)

emu.run(code)
emu.update_data()

print(emu.REGISTERS)

########

emu.uc.context_restore(context)

emu.update_data()

print(emu.REGISTERS)

