import React, {useMemo} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

import { decToHexString } from '../../utils/utils';

export default function G64Regs({emulator_data}) {

  const rows = useMemo(
    () => [
      {
        name1: "R8",
        value1: decToHexString(emulator_data.REGISTERS["R8"], 8),
        name2: "R12",
        value2: decToHexString(emulator_data.REGISTERS["R12"], 8),
      },
      {
        name1: "R9",
        value1: decToHexString(emulator_data.REGISTERS["R9"], 8),
        name2: "R13",
        value2: decToHexString(emulator_data.REGISTERS["R13"], 8),
      },
      {
        name1: "R10",
        value1: decToHexString(emulator_data.REGISTERS["R10"], 8),
        name2: "R14",
        value2: decToHexString(emulator_data.REGISTERS["R14"], 8),
      },
      {
        name1: "R11",
        value1: decToHexString(emulator_data.REGISTERS["R11"], 8),
        name2: "R15",
        value2: decToHexString(emulator_data.REGISTERS["R15"], 8),
      }
    ], [emulator_data]
  )

  return (
    <div style={{padding: "2px"}}>
      <TableContainer component={Paper} style={{boxShadow: "none"}}>
        <Table size="small" aria-label="a dense table" padding="none">
          <TableBody>
            {rows.map((row) => (
              <TableRow 
                key={row.name}
                sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
              >
                <TableCell component="th" scope="row" style={{color: "#76b5c5"}}>
                  {row.name1}
                </TableCell>
                <TableCell align="center">{row.value1}</TableCell>
                <TableCell component="th" scope="row" style={{color: "#76b5c5"}}>
                  {row.name2}
                </TableCell>
                <TableCell align="center">{row.value2}</TableCell>  
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}
