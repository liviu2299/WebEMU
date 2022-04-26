import React, { useMemo } from 'react'
import { useTable, useBlockLayout } from 'react-table'
import { FixedSizeList } from 'react-window'

import { decToHex, decToASCII } from "../../utils/utils"

export default function Memory({ emulator_data }) {

    const data = useMemo(
      () => {
        let temp = new Array(0)
        for(let i=0; i<emulator_data.MEMORY.length; i++){
          if(i%16 === 0){
            temp.push({
              addr: decToHex(Object.keys(emulator_data.MEMORY[i])[0]),
              value1: decToHex(Object.values(emulator_data.MEMORY[i])[0]),
              value2: decToHex(Object.values(emulator_data.MEMORY[i+1])[0]),
              value3: decToHex(Object.values(emulator_data.MEMORY[i+2])[0]),
              value4: decToHex(Object.values(emulator_data.MEMORY[i+3])[0]),
              value5: decToHex(Object.values(emulator_data.MEMORY[i+4])[0]),
              value6: decToHex(Object.values(emulator_data.MEMORY[i+5])[0]),
              value7: decToHex(Object.values(emulator_data.MEMORY[i+6])[0]),
              value8: decToHex(Object.values(emulator_data.MEMORY[i+7])[0]),
              value9: decToHex(Object.values(emulator_data.MEMORY[i+8])[0]),
              value10: decToHex(Object.values(emulator_data.MEMORY[i+9])[0]),
              value11: decToHex(Object.values(emulator_data.MEMORY[i+10])[0]),
              value12: decToHex(Object.values(emulator_data.MEMORY[i+11])[0]),
              value13: decToHex(Object.values(emulator_data.MEMORY[i+12])[0]),
              value14: decToHex(Object.values(emulator_data.MEMORY[i+13])[0]),
              value15: decToHex(Object.values(emulator_data.MEMORY[i+14])[0]),
              value16: decToHex(Object.values(emulator_data.MEMORY[i+15])[0]),
              ascii1: decToASCII(Object.values(emulator_data.MEMORY[i])[0]),
              ascii2: decToASCII(Object.values(emulator_data.MEMORY[i+1])[0]),
              ascii3: decToASCII(Object.values(emulator_data.MEMORY[i+2])[0]),
              ascii4: decToASCII(Object.values(emulator_data.MEMORY[i+3])[0]),
              ascii5: decToASCII(Object.values(emulator_data.MEMORY[i+4])[0]),
              ascii6: decToASCII(Object.values(emulator_data.MEMORY[i+5])[0]),
              ascii7: decToASCII(Object.values(emulator_data.MEMORY[i+6])[0]),
              ascii8: decToASCII(Object.values(emulator_data.MEMORY[i+7])[0]),
              ascii9: decToASCII(Object.values(emulator_data.MEMORY[i+8])[0]),
              ascii10: decToASCII(Object.values(emulator_data.MEMORY[i+9])[0]),
              ascii11: decToASCII(Object.values(emulator_data.MEMORY[i+10])[0]),
              ascii12: decToASCII(Object.values(emulator_data.MEMORY[i+11])[0]),
              ascii13: decToASCII(Object.values(emulator_data.MEMORY[i+12])[0]),
              ascii14: decToASCII(Object.values(emulator_data.MEMORY[i+13])[0]),
              ascii15: decToASCII(Object.values(emulator_data.MEMORY[i+14])[0]),
              ascii16: decToASCII(Object.values(emulator_data.MEMORY[i+15])[0]),
            })
          }
        }
        return temp
      },
      [emulator_data]
    )

    const columns = useMemo(
        () => [
          {
            accessor: 'addr', // accessor is the "key" in the data
          },
          {
            accessor: 'value1',
          },
          {
            accessor: 'value2',
          },
          {
            accessor: 'value3',
          },
          {
            accessor: 'value4',
          },
          {
            accessor: 'value5',
          },
          {
            accessor: 'value6',
          },
          {
            accessor: 'value7',
          },
          {
            accessor: 'value8',
          },
          {
            accessor: 'value9',
          },
          {
            accessor: 'value10',
          },
          {
            accessor: 'value11',
          },
          {
            accessor: 'value12',
          },
          {
            accessor: 'value13',
          },
          {
            accessor: 'value14',
          },
          {
            accessor: 'value15',
          },
          {
            accessor: 'value16',
          },
          {
            accessor: 'ascii1',
          },
          {
            accessor: 'ascii2',
          },
          {
            accessor: 'ascii3',
          },
          {
            accessor: 'ascii4',
          },
          {
            accessor: 'ascii5',
          },
          {
            accessor: 'ascii6',
          },
          {
            accessor: 'ascii7',
          },
          {
            accessor: 'ascii8',
          },
          {
            accessor: 'ascii9',
          },
          {
            accessor: 'ascii10',
          },
          {
            accessor: 'ascii11',
          },
          {
            accessor: 'ascii12',
          },
          {
            accessor: 'ascii13',
          },
          {
            accessor: 'ascii14',
          },
          {
            accessor: 'ascii15',
          },
          {
            accessor: 'ascii16',
          },
        ],
        []
    )

    const {
        getTableProps,
        getTableBodyProps,
        rows,
        prepareRow,
    } = useTable({ columns, data }, useBlockLayout)
   

    const RenderRow = React.useCallback(
        ({ index, style }) => {
          const row = rows[index]
          prepareRow(row)
          return (
            <div
              {...row.getRowProps({
                style,
              })}
              className="tr"
            >
              {row.cells.map(cell => {
                return (
                  <div {...cell.getCellProps()} className="td">
                    {cell.render('Cell')}
                  </div>
                )
              })}
            </div>
          )
        },
        [prepareRow, rows]
    )

    return (
        <div {...getTableProps()} className="table">

          <div {...getTableBodyProps()}>
            <FixedSizeList
              height={300}
              itemCount={rows.length}
              itemSize={20}
              width="100%"
            >
              {RenderRow}
            </FixedSizeList>
          </div>
        </div>
      )
}