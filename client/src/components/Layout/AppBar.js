import * as React from 'react';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import Button from '@mui/material/Button';
import HelpRoundedIcon from '@mui/icons-material/HelpRounded';
import Tooltip from '@mui/material/Tooltip';

import { handleRun, handleAssemble, handleStep, handleHome } from "../../api/requests";

const ResponsiveAppBar = ({emulator, setEmulator, input}) => {

  return (
    <AppBar position="static">
      <Box style={{paddingLeft: '10px'}}>
        <Toolbar disableGutters
        variant="regular"
        style={{height: "3rem", minHeight: "3rem", maxHeight: "3rem"}}
        >

          <Box sx={{ flexGrow: 1, display: { xs: 'none', md: 'flex'}}}>
            <Box sx={{padding: '0.3rem'}}>
              <Button 
                variant= 'contained' 
                color='success'
                size="small"
                sx={{ my: 4,
                  minWidth: "30px",
                  maxWidth: "50px",
                  minHeight: "25px",
                  maxHeight: "25px",
                  boxShadow: 3,
                  color: 'white'
                }}
                onClick={ () => handleRun(sessionStorage.getItem('id'),setEmulator,input,emulator) }
              >
              Run
              </Button>
            </Box>

            <Box sx={{padding: '0.3rem'}}>
              <Button 
                variant= 'contained' 
                color='secondary'
                size="small"
                sx={{ my: 4,
                  minWidth: "90px",
                  maxWidth: "90px",
                  minHeight: "25px",
                  maxHeight: "25px",
                  boxShadow: 3,
                }}
                onClick={ () => handleAssemble(sessionStorage.getItem('id'),setEmulator,input,emulator) }
              >
              Assemble
              </Button>
            </Box>

            <Box sx={{padding: '0.3rem'}}>          
              <Button 
                variant= 'contained' 
                color='secondary'
                size="small"
                sx={{ my: 4,
                  minWidth: "30px",
                  maxWidth: "50px",
                  minHeight: "25px",
                  maxHeight: "25px",
                  boxShadow: 3,
                }}
                onClick={ () => handleStep(sessionStorage.getItem('id'),setEmulator,input,emulator) }
              >
              Step
              </Button>   
            </Box>  
          
          </Box>
          <Box sx={{marginRight: '0.5rem', marginTop: '0.5rem'}}>
            <Tooltip>
              <HelpRoundedIcon />
            </Tooltip>
          </Box>
        </Toolbar>
      </Box>
    </AppBar>
  );
};
export default ResponsiveAppBar;
