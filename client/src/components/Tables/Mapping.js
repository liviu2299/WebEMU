import React, {useEffect, useMemo, useState} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import Input from '@mui/material/Input';
import IconButton from '@mui/material/IconButton';

import EditIcon from '@mui/icons-material/Edit';
import DoneIcon from '@mui/icons-material/Done';
import RevertIcon from '@mui/icons-material/DoDisturb';

import { decToHexString } from "../../utils/utils"

import { initial_state } from '../../constants';

import { handleUpdateParameters } from '../../api/requests';

/*
      {(isEditMode) ? (
        <Input
          value={row[name]}
          name={name}
          onChange={e => onChange(e, row)}
        />
      ) : (
        row[name]
      )}
*/


const CustomTableCell = ({ row, name, onChange }) => {
  const { isEditMode } = row;
  if(!isEditMode || (row.name==="memory" && name==="value")){
    return (
      <TableCell align="left">
        {row[name]}
      </TableCell>
    )
  }
  if(isEditMode){
    return (
      <TableCell align="left">
        <Input
          value={row[name]}
          name={name}
          onChange={e => onChange(e, row)}
        />
      </TableCell>
    )
  }

};

export default function Mapping({client_id, emulator_data, setEmulator}) {

  const [rows, setRows] = useState([
    {
      id: "memory",
      name: "memory",
      value: decToHexString(emulator_data.MEMORY.starting_address),
      value2: decToHexString(emulator_data.MEMORY.starting_address + emulator_data.MEMORY.size),
      isEditMode: false
    },
    {
      id: ".stack",
      name: ".stack",
      value: decToHexString(emulator_data.STACK.starting_address),
      value2: decToHexString(emulator_data.STACK.starting_address + emulator_data.STACK.size),
      isEditMode: false
    },
  ])

  const [previous, setPrevious] = useState([])

  useEffect(() => {
    setRows([
      {
        id: "memory",
        name: "memory",
        value: decToHexString(emulator_data.MEMORY.starting_address),
        value2: decToHexString(emulator_data.MEMORY.starting_address + emulator_data.MEMORY.size),
        isEditMode: false
      },
      {
        id: ".stack",
        name: ".stack",
        value: decToHexString(emulator_data.STACK.starting_address),
        value2: decToHexString(emulator_data.STACK.starting_address + emulator_data.STACK.size),
        isEditMode: false
      },
    ])
  }, [emulator_data])

  const onToggleEditMode = id => {
    setRows(state => {
      return rows.map(row => {
        if (row.id === id) {
          return { ...row, isEditMode: !row.isEditMode };
        }
        return row;
      });
    });
    setPrevious(rows)
  };

  const onChange = (e, row) => {

    const value = e.target.value;
    const name = e.target.name;
    const { id } = row;

    const newRows = rows.map(row => {
      if (row.id === id) {
        return { ...row, [name]: value };
      }
      return row;
    });
    setRows(newRows);

  };

  const onRevert = () => {
      setRows(previous)
    };

  const onSubmit = id => {
    setRows(state => {
      return rows.map(row => {
        if (row.id === id) {
          return { ...row, isEditMode: !row.isEditMode };
        }
        return row;
      });
    });

    // TODO: Validation !!!

    // Setting new emulator parameters
    
      setEmulator(initial_state)
      setEmulator( (emulator) => ({
        ...emulator,
        MEMORY: {
          starting_address: emulator.MEMORY.starting_address,
          size: rows[0].value2-rows[0].value,
          data: new Array(rows[0].value2-rows[0].value).fill({ "0": 0 }),
        },
        STACK: {
          starting_address: Number(rows[1].value),
          size: rows[1].value2-rows[1].value,
        }
      }))
    
    // Updating server-side emulator parameters
    
    handleUpdateParameters(client_id, {options:{
      MEMORY: {
        size: rows[0].value2-rows[0].value,
      },
      STACK: {
        starting_address: Number(rows[1].value),
        size: rows[1].value2-rows[1].value,
      }
    }})

  }

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
                <CustomTableCell {... {row, name: "value", onChange}}/>
                <CustomTableCell {... {row, name: "value2", onChange}}/>
                <TableCell>
                {row.isEditMode ? (
                  <div>
                    <IconButton
                      aria-label="done"
                      onClick={() => onSubmit(row.id)}
                    >
                      <DoneIcon />
                    </IconButton>
                    <IconButton
                      aria-label="revert"
                      onClick={() => onRevert()}
                    >
                      <RevertIcon />
                    </IconButton>
                  </div>
                  ) : (
                  <IconButton
                    aria-label="delete"
                    onClick={() => onToggleEditMode(row.id)}
                  >
                    <EditIcon />
                  </IconButton>
                )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}
