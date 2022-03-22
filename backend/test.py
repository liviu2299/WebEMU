from emulator import Emulator

emu = Emulator()

code = []
code.append("mov ah, 3")
code.append("mov al, 2")
code.append("push 5")
print(code)


hex1 = "100350"
hex2 = "100400"

i_hex1 = int(hex1, 16)
i_hex2 = int(hex2, 16)

result = hex(i_hex2 - i_hex1)



print(hex1)
print(i_hex1)
print(result)


hex3 = 0x50
print(hex3)

print(0x100400 - 0x100350)




