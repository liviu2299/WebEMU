import React, {useMemo} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

import { decToHexString } from '../../utils/utils';

export default function GRegs({emulator_data}) {

  const rows = useMemo(
    () => [
      {
        name4: "AX",
        value4: decToHexString(emulator_data.REGISTERS["AX"], 4),
        nameh: "AH",
        valueh: decToHexString(emulator_data.REGISTERS["AH"], 2),
        namel: "AL",
        valuel: decToHexString(emulator_data.REGISTERS["AL"], 2)
      },
      {
        name4: "BX",
        value4: decToHexString(emulator_data.REGISTERS["BX"], 4),
        nameh: "BH",
        valueh: decToHexString(emulator_data.REGISTERS["BH"], 2),
        namel: "BL",
        valuel: decToHexString(emulator_data.REGISTERS["BL"], 2)
      },
      {
        name4: "CX",
        value4: decToHexString(emulator_data.REGISTERS["CX"], 4),
        nameh: "CH",
        valueh: decToHexString(emulator_data.REGISTERS["CH"], 2),
        namel: "CL",
        valuel: decToHexString(emulator_data.REGISTERS["CL"], 2)
      },
      {
        name4: "DX",
        value4: decToHexString(emulator_data.REGISTERS["DX"], 4),
        nameh: "DH",
        valueh: decToHexString(emulator_data.REGISTERS["DH"], 2),
        namel: "DL",
        valuel: decToHexString(emulator_data.REGISTERS["DL"], 2)
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
                  {row.name4}
                </TableCell>
                <TableCell align="center">{row.value4}</TableCell>
                <TableCell component="th" scope="row">
                  {row.nameh}
                </TableCell>
                <TableCell align="center">{row.valueh}</TableCell>  
                <TableCell component="th" scope="row">
                  {row.namel}
                </TableCell>
                <TableCell align="center">{row.valuel}</TableCell>  
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}
