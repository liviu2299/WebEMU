import React, { useMemo } from 'react'
import { useTable } from 'react-table'

import { decToHexString } from "../../utils/utils"

export default function ISTable({ emulator_data }) {

    const data = useMemo(
      () => [
        {
            name1: "RSI",
            value1: decToHexString(emulator_data.REGISTERS["RSI"], 8),
            name2: "RDI",
            value2: decToHexString(emulator_data.REGISTERS["RDI"], 8),
        },
        {
            name1: "RSP",
            value1: decToHexString(emulator_data.REGISTERS["RSP"], 8),
            name2: "RBP",
            value2: decToHexString(emulator_data.REGISTERS["RBP"], 8),
        },
        {
            name1: "RIP",
            value1: decToHexString(emulator_data.REGISTERS["RIP"], 8),
            name2: "EFLAGS",
            value2: decToHexString(emulator_data.REGISTERS["EFLAGS"], 8),
        },
      ],
      [emulator_data]
    )

    const columns = useMemo(
        () => [
          {
            accessor: 'name1', // accessor is the "key" in the data
          },
          {
            accessor: 'value1',
          },
          {
            accessor: 'name2',
          },
          {
            accessor: 'value2',
          }
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
