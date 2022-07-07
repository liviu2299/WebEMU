import React, { useMemo } from 'react'
import { useTable, useBlockLayout } from 'react-table'
import { FixedSizeList } from 'react-window'

import { decToHex, decToHexString, decToASCII } from "../../utils/utils"

import { CustomScrollbarsVirtualList } from '../Scrollbar/Scrollbar';

import styled from 'styled-components'

const Styles = styled.div`
.table {
  .tr {
    .td{
      text-align: center;
    }
    .td:first-child{
      text-align: center;
      width: 4.5rem;
      min-width: 4.5rem;
      max-width: 4.5rem;
      padding-right: 0.5rem;
      border-right: 1px solid white;
      color: #A3A163
    }
    .td:nth-child(2){
      margin-left: 0.5rem;
    }

    padding-right: 1rem
  }
}
`

export default function Stack({ emulator_data }) {

    const data = useMemo(
      () => {
        let temp = new Array(0)
        for(let i=(emulator_data.STACK.starting_address-emulator_data.MEMORY.starting_address); i<(emulator_data.STACK.starting_address-emulator_data.MEMORY.starting_address+emulator_data.STACK.size); i++){
          if(i%8 == 0){
            temp.push({
              addr: decToHexString(Object.keys(emulator_data.MEMORY.data[i])[0],6),
              value1: decToHex(Object.values(emulator_data.MEMORY.data[i])[0]),
              value2: decToHex(Object.values(emulator_data.MEMORY.data[i+1])[0]),
              value3: decToHex(Object.values(emulator_data.MEMORY.data[i+2])[0]),
              value4: decToHex(Object.values(emulator_data.MEMORY.data[i+3])[0]),
              value5: decToHex(Object.values(emulator_data.MEMORY.data[i+4])[0]),
              value6: decToHex(Object.values(emulator_data.MEMORY.data[i+5])[0]),
              value7: decToHex(Object.values(emulator_data.MEMORY.data[i+6])[0]),
              value8: decToHex(Object.values(emulator_data.MEMORY.data[i+7])[0]),
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
      <Styles>
        <div {...getTableProps()} className="table">

        <div {...getTableBodyProps()}>
          <FixedSizeList
            height={195}
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