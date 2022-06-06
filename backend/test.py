from emulator import Emulator
import jsonpickle



#1)
emu = Emulator()

code = []
code.append("mov rax, 3")

emu.run(code)
emu.update_data()

print(emu.MEMORY)
print('------------')

context = emu.uc.context_save()

#2)
emu2 = Emulator()

encoded = jsonpickle.encode(context)
decoded = jsonpickle.decode(encoded)
emu2.uc.context_restore(decoded)

emu2.update_data()
print(emu2.MEMORY)
print('------------')

# --------------------------

# I)
mem = emu.uc.mem_read(emu2.MEMORY["starting_address"], emu2.MEMORY["size"])#
encrypted_mem = bytes(mem)#

print(encrypted_mem)

emu2.uc.mem_write(emu2.MEMORY["starting_address"], bytes(encrypted_mem))##
emu2.update_data()##


print(emu2.MEMORY)







