import React, { useMemo } from 'react'
import { useTable } from 'react-table'

import { decToHexString } from "../utils"

export default function GRTable({ emulator_data }) {

    const data = useMemo(
      () => [
        {
            name8: "RAX",
            value8: decToHexString(emulator_data.REGISTERS["RAX"], 8),
            name4: "AX",
            value4: decToHexString(emulator_data.REGISTERS["AX"], 4),
            nameh: "AH",
            valueh: decToHexString(emulator_data.REGISTERS["AH"], 2),
            namel: "AL",
            valuel: decToHexString(emulator_data.REGISTERS["AL"], 2)
        },
        {
            name8: "RBX",
            value8: decToHexString(emulator_data.REGISTERS["RBX"], 8),
            name4: "BX",
            value4: decToHexString(emulator_data.REGISTERS["BX"], 4),
            nameh: "BH",
            valueh: decToHexString(emulator_data.REGISTERS["BH"], 2),
            namel: "BL",
            valuel: decToHexString(emulator_data.REGISTERS["BL"], 2)
        },
        {
            name8: "RCX",
            value8: decToHexString(emulator_data.REGISTERS["RCX"], 8),
            name4: "CX",
            value4: decToHexString(emulator_data.REGISTERS["CX"], 4),
            nameh: "CH",
            valueh: decToHexString(emulator_data.REGISTERS["CH"], 2),
            namel: "CL",
            valuel: decToHexString(emulator_data.REGISTERS["CL"], 2)
        },
        {
            name8: "RDX",
            value8: decToHexString(emulator_data.REGISTERS["RDX"], 8),
            name4: "DX",
            value4: decToHexString(emulator_data.REGISTERS["DX"], 4),
            nameh: "DH",
            valueh: decToHexString(emulator_data.REGISTERS["DH"], 2),
            namel: "DL",
            valuel: decToHexString(emulator_data.REGISTERS["DL"], 2)
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
          },
          {
            accessor: 'name4',
          },
          {
            accessor: 'value4',
          },
          {
            accessor: 'nameh',
          },
          {
            accessor: 'valueh',
          },
          {
            accessor: 'namel',
          },
          {
            accessor: 'valuel',
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
