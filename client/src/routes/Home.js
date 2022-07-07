import React, {useState, useEffect, useMemo} from "react";
import WebFont from 'webfontloader';

import uuid from 'react-uuid'

import Grid from '@mui/material/Grid';
import {BoxContainer,NavbarContainer,EditorContainer,RegsContainer,FlagsContainer,LogContainer,MappingContainer,StackContainer,MemoryContainer} from '../styles';

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
import AppBar from "../components/Layout/AppBar";

import { initial_state } from "../constants";

import { handleHome } from "../api/requests";

export default function Home() {

    const [input, setInput] = useState('');
    const [emulator, setEmulator] = useState(initial_state);
    const [stepValid, setStepValid] = useState(false)
    const [loading, setLoading] = useState(false)

    useEffect(() => {
      sessionStorage.setItem("id", uuid())
      handleHome(sessionStorage.getItem('id'))

      WebFont.load({
        google: {
          families: ['Roboto Mono']
        }
      });
    }, [])

    useEffect(() => {
      console.log(emulator)
    }, [emulator])

    useEffect(() => {
      if(emulator.ERROR !== "None") setStepValid(false)
      if(emulator.ERROR === "None") setStepValid(true)
    }, [emulator.ERROR])

    return (    
        <BoxContainer>
          <Grid container spacing={1}>
            <Grid item xs={12}>
              <NavbarContainer>
                <AppBar emulator={emulator} setEmulator={setEmulator} input={input} setStepValid={setStepValid} stepValid={stepValid} loading={loading} setLoading={setLoading}/>
              </NavbarContainer>
            </Grid>

            <Grid item xs={3.5}>
              <EditorContainer>
								<Code value={input} onChange={setInput} emulator_data={emulator}/>
              </EditorContainer>  
            </Grid>

            <Grid item xs={8.5}>
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
                    <div style={{borderBottom: '1px solid white', marginBottom: "10px", position: 'sticky', top: '0', }}>
                      Operation Logs
                    </div>
                    <Log logs={emulator.LOG} error={emulator.ERROR}/>
                  </LogContainer>
                </Grid>
                <Grid item xs={3}>
                  <MappingContainer>
                    <Mapping client_id ={sessionStorage.getItem('id')} emulator_data={emulator} setEmulator={setEmulator}/>
                  </MappingContainer>
                  <StackContainer>
                    <div style={{borderBottom: '1px solid white', marginBottom: "10px", position: 'sticky', top: '0'}}>
                      Stack Segment
                    </div>
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
        </BoxContainer>
    )
}
