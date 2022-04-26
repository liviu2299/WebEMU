import React, {useState} from 'react'
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import { styled } from '@mui/material/styles';

import Code from "../components/Code/Code"

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

export default function TextEditor() {

  const [code, setCode] = useState('');

  return (
    <Box>
      <div>
        Navbar
      </div>
      <Grid container spacing={2}>

        <Grid item xs={4}>
          <EditorContainer>
            <Code value={code} onChange={setCode}/>
          </EditorContainer>  
        </Grid>
        
        <Grid item xs={8}>
          <Grid container spacing={1}>
            <Grid item xs={3.5}>
              <RegsContainer>Regs</RegsContainer>
            </Grid>
            <Grid item xs={2.5}>
              <FlagsContainer>Flags</FlagsContainer>
            </Grid>
            <Grid item xs={6}>
              <SmthContainer>Junk</SmthContainer>
            </Grid>
            <Grid item xs={12}>
              <MemoryContainer>RAM</MemoryContainer>
            </Grid>
          </Grid>
        </Grid> 

      </Grid>
    </Box>
  )
}
