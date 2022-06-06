import React, {useEffect, useState} from 'react'

import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import Input from '@mui/material/Input';
import IconButton from '@mui/material/IconButton';
import TextField from '@mui/material/TextField';

import EditIcon from '@mui/icons-material/Edit';
import DoneIcon from '@mui/icons-material/Done';
import RevertIcon from '@mui/icons-material/DoDisturb';

import { decToHexString, between, between_eq } from "../../utils/utils"
import { initial_state } from '../../constants';
import { handleUpdateParameters } from '../../api/requests';

const CustomTableCell = ({ row, name, onChange, Validation }) => {
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
        <TextField     
          error={Validation(row,name)}
          id="outlined-error-helper-text"
          value={row[name]}
          name={name}
          onChange={e => onChange(e, row)}
          helperText={Validation(row,name) ? "Incorrect entry." : ""}
          variant="standard"
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
    {
      id: ".data",
      name: ".data",
      value: decToHexString(emulator_data.DATA.starting_address),
      value2: decToHexString(emulator_data.DATA.starting_address + emulator_data.DATA.size),
      isEditMode: false
    },
  ])

  const [previous, setPrevious] = useState([])
  const [error, setError] = useState(false)

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
      {
        id: ".data",
        name: ".data",
        value: decToHexString(emulator_data.DATA.starting_address),
        value2: decToHexString(emulator_data.DATA.starting_address + emulator_data.DATA.size),
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

  useEffect(() => {
    console.log(error)
  }, [error])

  const Validation = (row,column) => {
    const value = row[column]
    switch(row.id){
      case "memory": {
        if(column === "value2"){
          if(value < Number(rows[1].value2) || value < Number(rows[2].value2)){
            setError(true)
            return true
          }
          else{
            setError(false)
            return false
          }
        }
      }
      case ".stack": {
        if(column === "value"){
          if(between(value,Number(rows[2].value),Number(rows[2].value2)) || !between_eq(value,Number(rows[0].value),Number(rows[0].value2)) || value>=Number(rows[1].value2)){
            setError(true)
            return true
          }
          else{
            setError(false)
            return false
          }
        }
        if(column === "value2"){
          if(between(value,Number(rows[2].value),Number(rows[2].value2)) || !between_eq(value,Number(rows[0].value),Number(rows[0].value2)) || value<=Number(rows[1].value)) {
            setError(true)
            return true
          }
          else{
            setError(false)
            return false
          }
        }
      }
      case ".data": {
        if(column === "value"){
          if(between(value,Number(rows[1].value),Number(rows[1].value2)) || !between_eq(value,Number(rows[0].value),Number(rows[0].value2)) || value>=Number(rows[2].value2)){
            setError(true)
            return true
          }
          else{
            setError(false)
            return false
          }
        }
        if(column === "value2"){
          if(between(value,Number(rows[1].value),Number(rows[1].value2)) || !between_eq(value,Number(rows[0].value),Number(rows[0].value2)) || value<=Number(rows[2].value)){
            setError(true)
            return true
          }
          else{
            setError(false)
            return false
          }
        }
      }
    }
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
      setError(false)
  };

  const onSubmit = id => {

    // If !Validation onRevert() + return
    console.log(error)
    if(error) {
      onRevert()
      return;
    }
    console.log("saved")

    setRows(state => {
      return rows.map(row => {
        if (row.id === id) {
          return { ...row, isEditMode: !row.isEditMode };
        }
        return row;
      });
    });

    // Updating client-side emulator parameters
    
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
      },
      DATA: {
        starting_address: Number(rows[2].value),
        size: rows[2].value2-rows[2].value,
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
      },
      DATA: {
        starting_address: Number(rows[2].value),
        size: rows[2].value2-rows[2].value,
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
                <CustomTableCell {... {row, name: "value", onChange, Validation}}/>
                <CustomTableCell {... {row, name: "value2", onChange, Validation}}/>
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
