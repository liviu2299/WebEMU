import React, {useMemo} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

import { decToHexString } from '../../utils/utils';

export default function Regs({emulator_data}) {

  const rows = useMemo(
    () => [
      {
        name: "RAX",
        value: decToHexString(emulator_data.REGISTERS["RAX"], 16)
      },
      {
        name: "RBX",
        value: decToHexString(emulator_data.REGISTERS["RBX"], 16)
      },
      {
        name: "RCX",
        value: decToHexString(emulator_data.REGISTERS["RCX"], 16)
      },
      {
        name: "RDX",
        value: decToHexString(emulator_data.REGISTERS["RDX"], 16)
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
