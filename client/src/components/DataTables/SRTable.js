import React, { useMemo } from 'react'
import { useTable } from 'react-table'

import { decToHexString } from "../../utils/utils"

export default function SRTable({ emulator_data }) {

    const data = useMemo(
      () => [
        {
            name1: "CS",
            value1: decToHexString(emulator_data.REGISTERS["CS"], 4),
            name2: "DS",
            value2: decToHexString(emulator_data.REGISTERS["DS"], 4),
            name3: "SS",
            value3: decToHexString(emulator_data.REGISTERS["SS"], 4),
        },
        {
            name1: "ES",
            value1: decToHexString(emulator_data.REGISTERS["ES"], 4),
            name2: "FS",
            value2: decToHexString(emulator_data.REGISTERS["FS"], 4),
            name3: "GS",
            value3: decToHexString(emulator_data.REGISTERS["GS"], 4),
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
          },
          {
            accessor: 'name3',
          },
          {
            accessor: 'value3',
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
