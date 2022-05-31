import React, { useMemo } from 'react'
import { useTable, useBlockLayout } from 'react-table'
import { FixedSizeList } from 'react-window'

import { decToHex, decToHexString, decToASCII } from "../../utils/utils"

import styled from 'styled-components'

const Styles = styled.div`
.table {
  .tr {
    .td:first-child{
      text-align: left;
    }
    text-align: center;

  }
}
`

export default function Stack({ emulator_data }) {

    const data = useMemo(
      () => {
        let temp = new Array(0)
        for(let i=(emulator_data.STACK.starting_address-emulator_data.MEMORY.starting_address); i<(emulator_data.STACK.starting_address-emulator_data.MEMORY.starting_address+emulator_data.STACK.size); i++){
          temp.push({
            addr: decToHexString(Object.keys(emulator_data.MEMORY.data[i])[0]),
            value: decToHex(Object.values(emulator_data.MEMORY.data[i])[0]),
          })
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
            accessor: 'value',
          }
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
            height={224}
            itemCount={rows.length}
            itemSize={20}
            width="100%"
          >
            {RenderRow}
          </FixedSizeList>
        </div>
        </div>
      </Styles>
      )
}