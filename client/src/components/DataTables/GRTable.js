import React, { useMemo } from 'react'
import { useTable } from 'react-table'

import { decToHexString } from "../../utils/utils"

export default function GRTable({ emulator_data }) {

    const data = useMemo(
      () => [
        {
            name8: "RAX",
            value8: decToHexString(emulator_data.REGISTERS["RAX"], 16),
        },
        {
            name8: "RBX",
            value8: decToHexString(emulator_data.REGISTERS["RBX"], 16),
        },
        {
            name8: "RCX",
            value8: decToHexString(emulator_data.REGISTERS["RCX"], 16),
        },
        {
            name8: "RDX",
            value8: decToHexString(emulator_data.REGISTERS["RDX"], 16),
        },
      ],
      [emulator_data]
    )

    const columns = useMemo(
        () => [
          {
            accessor: 'name8', // accessor is the "key" in the data
          },
          {
            accessor: 'value8',
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
