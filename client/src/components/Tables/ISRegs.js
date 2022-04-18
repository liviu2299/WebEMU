import React, {useMemo} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

import { decToHexString } from '../../utils/utils';

export default function ISRegs({emulator_data}) {

  const rows = useMemo(
    () => [
      {
        name1: "RSI",
        value1: decToHexString(emulator_data.REGISTERS["RSI"], 8),
        name2: "RDI",
        value2: decToHexString(emulator_data.REGISTERS["RDI"], 8),
      },
      {
        name1: "RSP",
        value1: decToHexString(emulator_data.REGISTERS["RSP"], 8),
        name2: "RBP",
        value2: decToHexString(emulator_data.REGISTERS["RBP"], 8),
      },
      {
        name1: "RIP",
        value1: decToHexString(emulator_data.REGISTERS["RIP"], 8),
        name2: "EFLAGS",
        value2: decToHexString(emulator_data.REGISTERS["EFLAGS"], 8),
      }
    ], [emulator_data]
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
                  {row.name1}
                </TableCell>
                <TableCell align="center">{row.value1}</TableCell>
                <TableCell component="th" scope="row">
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
