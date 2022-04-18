import React, {useMemo} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

import { decToHexString } from '../../utils/utils';

export default function SRegs({emulator_data}) {

  const rows = useMemo(
    () => [
      {
        name1: "CS",
        value1: decToHexString(emulator_data.REGISTERS["CS"], 4),
        name2: "DS",
        value2: decToHexString(emulator_data.REGISTERS["DS"], 4),
        name3: "SS",
        value3: decToHexString(emulator_data.REGISTERS["SS"], 4),
      },
      {
        name1: "ES",
        value1: decToHexString(emulator_data.REGISTERS["ES"], 4),
        name2: "FS",
        value2: decToHexString(emulator_data.REGISTERS["FS"], 4),
        name3: "GS",
        value3: decToHexString(emulator_data.REGISTERS["GS"], 4),
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
                <TableCell component="th" scope="row">
                  {row.name3}
                </TableCell>
                <TableCell align="center">{row.value3}</TableCell>  
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}
