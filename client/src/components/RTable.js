import React, { useEffect, useMemo } from 'react'
import { useTable } from 'react-table'

export default function RTable({ emulator_data }) {

    const data = useMemo(
      () => {
        let temp = new Array(0)
        for(let i=0; i< Object.keys(emulator_data.REGISTERS).length; i++){
            temp.push({
              name: Object.keys(emulator_data.REGISTERS)[i],
              value: Object.values(emulator_data.REGISTERS)[i],
            })
        }
        return temp
      },
      [emulator_data]
    )

    const columns = useMemo(
        () => [
          {
            accessor: 'name', // accessor is the "key" in the data
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
    } = useTable({ columns, data })
   

    return (
      <div>
        <table {...getTableProps()} style={{ border: 'solid 1px black' }}>
          <tbody {...getTableBodyProps()}>
            {rows.map(row => {
            prepareRow(row)
            return (
                <tr {...row.getRowProps()}>
                {row.cells.map(cell => {
                    return (
                    <td
                        {...cell.getCellProps()}
                        style={{
                        border: 'solid 1px black'
                        }}
                    >
                        {cell.render('Cell')}
                    </td>
                    )
                })}
                </tr>
            )
            })}
          </tbody>
        </table>
        <br></br>
      </div>
    )
}
