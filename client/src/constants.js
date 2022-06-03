export const initial_state = {
          REGISTERS: {
            RAX: 0,
            RBX: 0,
            RCX: 0,
            RDX: 0,

            AX: 0,
            BX: 0,
            CX: 0,
            DX: 0,

            AH: 0,
            BH: 0,
            CH: 0,
            DH: 0,

            AL: 0,
            BL: 0,
            CL: 0,
            DL: 0,

            RSI: 0,
            RDI: 0,

            RBP: 0,
            RSP: 0,  

            RIP: 0,  

            CS: 0,
            DS: 0,
            ES: 0,
            FS: 0,
            SS: 0,
            GS: 0,

            R8: 0,
            R9: 0,
            R10: 0,
            R11: 0,
            R12: 0,
            R13: 0,
            R14: 0,
            R15: 0,

            EFLAGS: 0           
          },
          MEMORY: {
            size: 0x100400-0x100000,
            data: new Array(1024).fill({ "0": 0 }),
            starting_address: 0x100000,
          },
          STACK: {
            size: 0x100400-0x100350,
            starting_address: 0x100350,
          },
          ERROR: "None",
          LOG: [],
          STATE: 0
}