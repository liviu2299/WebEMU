import React, {useState, useEffect, useMemo} from "react";

import Box from '@mui/material/Box';
import AppBar from '@mui/material/AppBar';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import { styled } from '@mui/material/styles';

import Code from "../components/Code/Code"
import Regs from "../components/Tables/Regs";
import GRegs from "../components/Tables/GRegs";
import ISRegs from "../components/Tables/ISRegs";
import SRegs from "../components/Tables/SRegs";
import Flags from "../components/Tables/Flags";
import Memory from "../components/Tables/Memory";

import "./Layout.css"

const EditorContainer = styled(Paper)(({ theme }) => ({
    ...theme.typography.body2,
    color: theme.palette.text.primary,
    backgroundColor: "antiquewhite",
    height: '90vh',
    position: 'relative'
  }));
const RegsContainer = styled(Paper)(({ theme }) => ({
    ...theme.typography.body2,
    color: theme.palette.text.primary,
    backgroundColor: "antiquewhite",
    height: '50vh',
    position: 'relative'
  }));
const FlagsContainer = styled(Paper)(({ theme }) => ({
    ...theme.typography.body2,
    color: theme.palette.text.primary,
    backgroundColor: "antiquewhite",
    height: '50vh',
    position: 'relative'
  }));
const SmthContainer = styled(Paper)(({ theme }) => ({
    ...theme.typography.body2,
    color: theme.palette.text.primary,
    backgroundColor: "antiquewhite",
    height: '50vh',
    position: 'relative'
  }));
const MemoryContainer = styled(Paper)(({ theme }) => ({
    ...theme.typography.body2,
    color: theme.palette.text.primary,
    backgroundColor: "antiquewhite",
    height: '39vh',
    position: 'relative'
  }));  

export default function Home() {

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

    const [input, setInput] = useState('');

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

    return (    
        <Box>
          <div className="navbar">
            Navbar
          	<button onClick={ handleRun }>Run</button>
            <button onClick={ handleAssemble }>Assemble</button>
					</div>
          <Grid container spacing={2}>

            <Grid item xs={4}>
              <EditorContainer>
								<Code value={input} onChange={setInput}/>
              </EditorContainer>  
            </Grid>

            <Grid item xs={8}>
              <Grid container spacing={1}>
                <Grid item xs={3.5}>
                  <RegsContainer>
                    <Regs emulator_data={emulator}/>
										<GRegs emulator_data={emulator}/>
                    <ISRegs emulator_data={emulator}/>
										<SRegs emulator_data={emulator}/>
									</RegsContainer>
                </Grid>
              	<Grid item xs={2.5}>
                	<FlagsContainer>
                    <Flags emulator_data={emulator}/>
                  </FlagsContainer>
              		</Grid>
              	<Grid item xs={6}>
                  <SmthContainer>Other</SmthContainer>
                </Grid>
                <Grid item xs={12}>
                  <MemoryContainer>
                    <Memory emulator_data={emulator}/>
                  </MemoryContainer>
                </Grid>
              </Grid>
            </Grid> 
          </Grid>
        </Box>
    )
}
