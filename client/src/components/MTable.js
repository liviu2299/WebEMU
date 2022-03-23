import React, { useEffect, useMemo } from 'react'
import { useTable, useBlockLayout } from 'react-table'
import { FixedSizeList } from 'react-window'

export default function RTable({ emulator_data }) {

    const data = useMemo(
      () => {
        let temp = new Array(0)
        emulator_data.MEMORY.forEach(i => {
            temp.push({
                addr: Object.keys(i)[0],
                value: Object.values(i)[0],   
            })
        })
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
            accessor: 'value',
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
              height={400}
              itemCount={rows.length}
              itemSize={20}
              width={180}
            >
              {RenderRow}
            </FixedSizeList>
          </div>
        </div>
      )
}

