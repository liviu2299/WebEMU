import React, { useMemo } from 'react'
import { useTable } from 'react-table'

import { decToBinaryString } from "../../utils/utils"

export default function FlagsTable({ emulator_data }) {

    const data = useMemo(
      () => {
        
        let flags = decToBinaryString(emulator_data.REGISTERS["EFLAGS"]).split("").reverse()

        return [
        {
            name: "Carry",
            value: flags[0]
        },
        {
            name: "Parity",
            value: flags[2]
        },
        {
            name: "Adjust",
            value: flags[4]
        },
        {
            name: "Zero",
            value: flags[6]
        },
        {
            name: "Sign",
            value: flags[7]
        },
        {
            name: "Trap",
            value: flags[8]
        },
        {
            name: "Interrupt enable",
            value: flags[9]
        },
        {
            name: "Direction",
            value: flags[10]
        },
        {
            name: "Overflow",
            value: flags[11]
        },
        {
            name: "Resume",
            value: flags[16]
        },
        {
            name: "Virtual 8086",
            value: flags[17]
        },
        {
            name: "Alignment check",
            value: flags[18]
        },
        {
            name: "Virtual interrupt",
            value: flags[19]
        },
        {
            name: "Virtual interrupt pending ",
            value: flags[20]
        },
        {
            name: "CPUID",
            value: flags[21]
        },
      ]},
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
