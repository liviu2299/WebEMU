import React, {useState, useEffect, useMemo} from "react";

import uuid from 'react-uuid'

import Box from '@mui/material/Box';
import AppBar from '@mui/material/AppBar';
import Grid from '@mui/material/Grid';
import {NavbarContainer,EditorContainer,RegsContainer,FlagsContainer,LogContainer,MappingContainer,StackContainer,MemoryContainer} from './styles';

import Code from "../components/Code/Code"
import Regs from "../components/Tables/Regs";
import GRegs from "../components/Tables/GRegs";
import ISRegs from "../components/Tables/ISRegs";
import SRegs from "../components/Tables/SRegs";
import G64Regs from "../components/Tables/G64Regs";
import Flags from "../components/Tables/Flags";
import Memory from "../components/Tables/Memory";
import Log from "../components/Log/Log";
import Mapping from "../components/Tables/Mapping";
import Stack from "../components/Tables/Stack";

import { handleRun, handleAssemble, handleStep, handleHome } from "../api/requests";

import { initial_state } from "../constants";

export default function Home() {

    const [input, setInput] = useState('');
    const [emulator, setEmulator] = useState(initial_state);
    const [id, setId] = useState(uuid());

    useEffect(() => {
      handleHome(id)
    }, [])

    useEffect(() => {
      console.log(emulator)
    }, [emulator])

    return (    
        <Box>
          <NavbarContainer>
            Navbar
          	<button onClick={ () => handleRun(id,setEmulator,input,emulator) }>Run</button>
            <button onClick={ () => handleAssemble(id,setEmulator,input,emulator) }>Assemble</button>
            <button onClick={ () => handleStep(id,setEmulator,input,emulator) }>Step</button>
					</NavbarContainer>
          <Grid container spacing={2}>

            <Grid item xs={4}>
              <EditorContainer>
								<Code value={input} onChange={setInput} emulator_data={emulator}/>
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
                    <G64Regs emulator_data={emulator}/>
									</RegsContainer>
                </Grid>
              	<Grid item xs={2.5}>
                	<FlagsContainer>
                    <Flags emulator_data={emulator}/>
                  </FlagsContainer>
              		</Grid>
              	<Grid item xs={3}>
                  <LogContainer>
                    Logs
                    <Log logs={emulator.LOG}/>
                  </LogContainer>
                </Grid>
                <Grid item xs={3}>
                  <MappingContainer>
                    Mapping
                    <Mapping client_id ={id} emulator_data={emulator} setEmulator={setEmulator}/>
                  </MappingContainer>
                  <StackContainer>
                    Stack
                    <Stack emulator_data={emulator}/>
                  </StackContainer>
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
