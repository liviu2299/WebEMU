import * as React from 'react';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Container from '@mui/material/Container';
import Button from '@mui/material/Button';

import { handleRun, handleAssemble, handleStep, handleHome } from "../../api/requests";

const ResponsiveAppBar = ({emulator, setEmulator, input}) => {

  return (
    <AppBar position="static">
      <Container maxWidth="xxl">
        <Toolbar disableGutters
        variant="regular"
        style={{height: "3rem", minHeight: "3rem", maxHeight: "3rem"}}
        >
          <Typography
            variant="h6"
            noWrap
            component="a"
            href="/"
            sx={{
              mr: 2,
              display: { xs: 'none', md: 'flex' },
              fontFamily: 'monospace',
              fontWeight: 400,
              letterSpacing: '.3rem',
              color: 'inherit',
              textDecoration: 'none',
            }}
          >
            Home
          </Typography>

          <Box sx={{ flexGrow: 1, display: { xs: 'none', md: 'flex' }}}>
            <Button 
              sx={{ my: 2, color: 'white', display: 'block' }}
              onClick={ () => handleRun(sessionStorage.getItem('id'),setEmulator,input,emulator) }
            >
            Run
            </Button>
            <Button 
              sx={{ my: 2, color: 'white', display: 'block' }}
              onClick={ () => handleAssemble(sessionStorage.getItem('id'),setEmulator,input,emulator) }
            >
            Assemble
            </Button>
            <Button 
              sx={{ my: 2, color: 'white', display: 'block' }}
              onClick={ () => handleStep(sessionStorage.getItem('id'),setEmulator,input,emulator) }
            >
            Step
            </Button>            
          </Box>
        </Toolbar>
      </Container>
    </AppBar>
  );
};
export default ResponsiveAppBar;
