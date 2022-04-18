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
          name: "Carry",
          value: flags[0]
      },
      {
          name: "Parity",
          value: flags[2]
      },
      {
          name: "Adjust",
          value: flags[4]
      },
      {
          name: "Zero",
          value: flags[6]
      },
      {
          name: "Sign",
          value: flags[7]
      },
      {
          name: "Trap",
          value: flags[8]
      },
      {
          name: "Interrupt enable",
          value: flags[9]
      },
      {
          name: "Direction",
          value: flags[10]
      },
      {
          name: "Overflow",
          value: flags[11]
      },
      {
          name: "Resume",
          value: flags[16]
      },
      {
          name: "Virtual 8086",
          value: flags[17]
      },
      {
          name: "Alignment check",
          value: flags[18]
      },
      {
          name: "Virtual interrupt",
          value: flags[19]
      },
      {
          name: "Virtual interrupt pending ",
          value: flags[20]
      },
      {
          name: "CPUID",
          value: flags[21]
      },
    ]},
    [emulator_data]
  )

  return (
    <div>
      <TableContainer component={Paper}>
        <Table size="small" aria-label="a dense table" padding="none">
          <TableBody>
            {rows.map((row) => (
              <TableRow 
                key={row.name}
                sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
              >
                <TableCell component="th" scope="row">
                  {row.name}
                </TableCell>
                <TableCell align="right">{row.value}</TableCell>  
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}
