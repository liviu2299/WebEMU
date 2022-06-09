import React, { useMemo, useState, useEffect, useCallback } from 'react'
import { useTable, useBlockLayout } from 'react-table'
import { FixedSizeList } from 'react-window'

import { CustomScrollbarsVirtualList } from '../Scrollbar/Scrollbar';

import styled from 'styled-components'

import { decToHex, decToHexString, decToASCII, isEmpty, check } from "../../utils/utils"

const Styles = styled.div`
.table {

  .tr {
    .td:first-child{
      width: 5rem;
      min-width: 5rem;
      max-width: 5rem;
      border-right: 1px solid white;
    }
    .td:nth-child(17){
      border-right: 1px solid white;
    }
    text-align: center;
  }
}`

export default function Memory({ emulator_data }) {

    const [stepInstruction, setStepInstruction] = useState({});

    const data = useMemo(
      () => {
        let temp = new Array(0)
        for(let i=0; i<emulator_data.MEMORY.size; i++){
          if(i%16 === 0){
            temp.push({
              addr: decToHexString(Object.keys(emulator_data.MEMORY.data[i])[0]),
              value1: decToHex(Object.values(emulator_data.MEMORY.data[i])[0]),
              value2: decToHex(Object.values(emulator_data.MEMORY.data[i+1])[0]),
              value3: decToHex(Object.values(emulator_data.MEMORY.data[i+2])[0]),
              value4: decToHex(Object.values(emulator_data.MEMORY.data[i+3])[0]),
              value5: decToHex(Object.values(emulator_data.MEMORY.data[i+4])[0]),
              value6: decToHex(Object.values(emulator_data.MEMORY.data[i+5])[0]),
              value7: decToHex(Object.values(emulator_data.MEMORY.data[i+6])[0]),
              value8: decToHex(Object.values(emulator_data.MEMORY.data[i+7])[0]),
              value9: decToHex(Object.values(emulator_data.MEMORY.data[i+8])[0]),
              value10: decToHex(Object.values(emulator_data.MEMORY.data[i+9])[0]),
              value11: decToHex(Object.values(emulator_data.MEMORY.data[i+10])[0]),
              value12: decToHex(Object.values(emulator_data.MEMORY.data[i+11])[0]),
              value13: decToHex(Object.values(emulator_data.MEMORY.data[i+12])[0]),
              value14: decToHex(Object.values(emulator_data.MEMORY.data[i+13])[0]),
              value15: decToHex(Object.values(emulator_data.MEMORY.data[i+14])[0]),
              value16: decToHex(Object.values(emulator_data.MEMORY.data[i+15])[0]),
              ascii1: decToASCII(Object.values(emulator_data.MEMORY.data[i])[0]),
              ascii2: decToASCII(Object.values(emulator_data.MEMORY.data[i+1])[0]),
              ascii3: decToASCII(Object.values(emulator_data.MEMORY.data[i+2])[0]),
              ascii4: decToASCII(Object.values(emulator_data.MEMORY.data[i+3])[0]),
              ascii5: decToASCII(Object.values(emulator_data.MEMORY.data[i+4])[0]),
              ascii6: decToASCII(Object.values(emulator_data.MEMORY.data[i+5])[0]),
              ascii7: decToASCII(Object.values(emulator_data.MEMORY.data[i+6])[0]),
              ascii8: decToASCII(Object.values(emulator_data.MEMORY.data[i+7])[0]),
              ascii9: decToASCII(Object.values(emulator_data.MEMORY.data[i+8])[0]),
              ascii10: decToASCII(Object.values(emulator_data.MEMORY.data[i+9])[0]),
              ascii11: decToASCII(Object.values(emulator_data.MEMORY.data[i+10])[0]),
              ascii12: decToASCII(Object.values(emulator_data.MEMORY.data[i+11])[0]),
              ascii13: decToASCII(Object.values(emulator_data.MEMORY.data[i+12])[0]),
              ascii14: decToASCII(Object.values(emulator_data.MEMORY.data[i+13])[0]),
              ascii15: decToASCII(Object.values(emulator_data.MEMORY.data[i+14])[0]),
              ascii16: decToASCII(Object.values(emulator_data.MEMORY.data[i+15])[0]),
            })
          }
        }
        return temp
      },
      [emulator_data.MEMORY]
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

    useEffect(() => {

      if(!isEmpty(emulator_data.STEP_INFO)){
        const addr = emulator_data.STEP_INFO["address"]
        const size = emulator_data.STEP_INFO["size"]

        let temp = []
        const start = addr - 0x100000
        const end = start + Number(size)

        for(let i=0; i<end-start; i++){
          const pos = start + i
          const row = Math.trunc(pos/16)
          const col = pos%16 + 1
          temp.push({row:row, col:col})
        }

        setStepInstruction(temp)

      }
      else setStepInstruction({})

    },[emulator_data.STEP_INFO])

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
              {row.cells.map((cell,index) => {
                return (
                  <div stepInstruction={stepInstruction} {...cell.getCellProps(
                    {
                      className: cell.column.className,
                      style: {
                        backgroundColor: check(cell.row.index,index,stepInstruction) ? "#727272" : null
                      }
                    }
                    )} className="td">
                    {cell.render('Cell')}
                  </div>
                )
              })}
            </div>
          )
        },
        [prepareRow, rows, stepInstruction]
    )

    return (
      <Styles>
        <div {...getTableProps()} className="table">

        <div {...getTableBodyProps()}>
          <FixedSizeList
            height={280}
            itemCount={rows.length}
            itemSize={20}
            width="100%"
            outerElementType={CustomScrollbarsVirtualList}
          >
            {RenderRow}
          </FixedSizeList>
        </div>
        </div>
      </Styles>
      )
}