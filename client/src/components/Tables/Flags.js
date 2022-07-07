import React, {useMemo} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

import { decToBinaryString } from '../../utils/utils';

export default function Flags({emulator_data}) {

  const rows = useMemo(
    () => {
      
      let flags = decToBinaryString(emulator_data.REGISTERS["EFLAGS"]).split("").reverse()

      return [
      {   
          number: "0",
          name: "Carry",
          value: flags[0]
      },
      {
        number: "2",
          name: "Parity",
          value: flags[2]
      },
      {
        number: "4",
          name: "Adjust",
          value: flags[4]
      },
      {
        number: "6",
          name: "Zero",
          value: flags[6]
      },
      {
        number: "7",
          name: "Sign",
          value: flags[7]
      },
      {
        number: "8",
          name: "Trap",
          value: flags[8]
      },
      {
        number: "9",
          name: "Interrupt enable",
          value: flags[9]
      },
      {
        number: "10",
          name: "Direction",
          value: flags[10]
      },
      {
        number: "11",
          name: "Overflow",
          value: flags[11]
      },
      {
        number: "16",
          name: "Resume",
          value: flags[16]
      },
      {
        number: "17",
          name: "Virtual 8086",
          value: flags[17]
      },
      {
        number: "18",
          name: "Alignment check",
          value: flags[18]
      },
      {
        number: "19",
          name: "Virtual interrupt",
          value: flags[19]
      },
      {
        number: "20",
          name: "VI pending",
          value: flags[20]
      },
      {
        number: "21",
          name: "CPUID",
          value: flags[21]
      },
    ]},
    [emulator_data]
  )

  const explicit = useMemo(
    () => {
      
      let flags = decToBinaryString(emulator_data.REGISTERS["EFLAGS"]).split("").reverse()
      return flags
    },
    [emulator_data]
  )


  return (
    <div>
      <TableContainer component={Paper} style={{height: '100%', boxShadow: "none"}}>
        <Table size="small" aria-label="a dense table" padding="none">
          <TableBody>
            {rows.map((row) => (
              <TableRow 
                key={row.name}
                sx={{ '&:last-child td, &:last-child th': { border: 0 }}}
                style={{height: '1.36rem'}}
              >
                <TableCell component="th" scope="row" style={{color: "#76b5c5"}}>
                  {row.name}
                </TableCell>
                {row.value == 1 ? (
                  <TableCell align="right" style={{color: '#EF5A5A'}}>{row.value}</TableCell>  
                ):
                (
                  <TableCell align="right">{row.value}</TableCell>  
                )}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <div style={{marginTop: "3px", borderTop: '1px solid white', paddingTop: "3px"}}>
        {explicit.map((flag, index) => {
          if(flag == 1) return (<div style={{float: "left", paddingRight: '2.3px', paddingLeft: '2.3px', color: '#EF5A5A'}}>{flag}</div>)
          if(flag == 0) return (<div style={{float: "left", paddingRight: '2.3px', paddingLeft: '2.3px'}}>{flag}</div>)}
        )}
      </div>
    </div>
  )
}
