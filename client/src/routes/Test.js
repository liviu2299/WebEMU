import React, {useState, useEffect, useMemo} from "react";

import Editor from '../components/Editor/Editor';

import GRTable from "../components/DataTables/GRTable";
import ISTable from "../components/DataTables/ISTable";
import SRTable from "../components/DataTables/SRTable";
import FlagsTable from "../components/DataTables/FlagsTable";
import MTable from "../components/DataTables/MTable";
import RTable from "../components/DataTables/RTable";

import Regs from "../components/Tables/Regs";

export default function Test() {

    const initial_state = useMemo(() => ({
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

            EFLAGS: 0           
        },
        MEMORY: new Array(1024).fill({ "0": 0 }),
        ERROR: "None"
    }), [])

    const [input, setInput] = useState({});
    const [emulator, setEmulator] = useState(initial_state);

    const handleRun = () => {
        (async () => {
            const rawResponse = await fetch("/compute", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ data: input }),
            });

            const content = await rawResponse.json();

            if(content.error === "None")    
                setEmulator({MEMORY: content.memory, REGISTERS: content.registers, ERROR: content.error})
            else
                setEmulator({...emulator, ERROR: content.error})

        })();
    }

    const handleAssemble = () => {
        (async () => {
            const rawResponse = await fetch("/compile", {
                method: "POST",
                headers: {
                    Accept: "application/json",
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ data: input }),
            });

            const content = await rawResponse.json();

            if(content.error === "None")   
                setEmulator({...emulator, MEMORY: content.memory, ERROR: content.error})
            else
                setEmulator({...emulator, ERROR: content.error})

        })();
    }   

    useEffect(() => {
        console.log(emulator)
    }, [emulator])

    return (
        <div>
            <Editor
                placeHolder = "Type your code here"
                onChange = {(e) => setInput(e.target.value)}
            />
            <button onClick={ handleRun }>Run</button>
            <button onClick={ handleAssemble }>Assemble</button>
            
            <GRTable emulator_data={emulator}/>
            <Regs emulator_data={emulator}/>
            <RTable emulator_data={emulator}/>
            <ISTable emulator_data={emulator}/>
            <SRTable emulator_data={emulator}/>
            <FlagsTable emulator_data={emulator}/>

            <MTable emulator_data={emulator}/>
        </div>
    );
}
