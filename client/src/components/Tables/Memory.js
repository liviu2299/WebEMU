import React, {useMemo} from 'react';
import PropTypes from 'prop-types';
import clsx from 'clsx';
import { withStyles } from '@mui/styles';
import { createTheme } from '@mui/material/styles';
import TableCell from '@mui/material/TableCell';
import Paper from '@mui/material/Paper';
import { AutoSizer, Column, Table } from 'react-virtualized';

import { decToHex } from '../../utils/utils';

const styles = (theme) => ({
  flexContainer: {
    display: 'flex',
    alignItems: 'center',
    boxSizing: 'border-box',
  },
  table: {
    // temporary right-to-left patch, waiting for
    // https://github.com/bvaughn/react-virtualized/issues/454
    '& .ReactVirtualized__Table__headerRow': {
      ...(theme.direction === 'rtl' && {
        paddingLeft: '0 !important',
      }),
      ...(theme.direction !== 'rtl' && {
        paddingRight: undefined,
      }),
    },
  },
  tableRow: {
    cursor: 'pointer',
  },
  tableRowHover: {
    '&:hover': {
      backgroundColor: theme.palette.grey[200],
    },
  },
  tableCell: {
    flex: 1,
  },
  noClick: {
    cursor: 'initial',
  },
});

class MuiVirtualizedTable extends React.PureComponent {
  static defaultProps = {
    headerHeight: 48,
    rowHeight: 48,
  };

  getRowClassName = ({ index }) => {
    const { classes, onRowClick } = this.props;

    return clsx(classes.tableRow, classes.flexContainer, {
      [classes.tableRowHover]: index !== -1 && onRowClick != null,
    });
  };

  cellRenderer = ({ cellData, columnIndex }) => {
    const { columns, classes, rowHeight, onRowClick } = this.props;
    return (
      <TableCell
        component="div"
        className={clsx(classes.tableCell, classes.flexContainer, {
          [classes.noClick]: onRowClick == null,
        })}
        variant="body"
        style={{ height: rowHeight }}
        align={
          (columnIndex != null && columns[columnIndex].numeric) || false
            ? 'right'
            : 'left'
        }
      >
        {cellData}
      </TableCell>
    );
  };

  headerRenderer = ({ label, columnIndex }) => {
    const { headerHeight, columns, classes } = this.props;

    return (
      <TableCell
        component="div"
        className={clsx(classes.tableCell, classes.flexContainer, classes.noClick)}
        variant="head"
        style={{ height: headerHeight }}
        align={columns[columnIndex].numeric || false ? 'right' : 'left'}
      >
        <span>{label}</span>
      </TableCell>
    );
  };

  render() {
    const { classes, columns, rowHeight, headerHeight, ...tableProps } = this.props;
    return (
      <AutoSizer>
        {({ height, width }) => (
          <Table
            height={height}
            width={width}
            rowHeight={rowHeight}
            gridStyle={{
              direction: 'inherit',
            }}
            headerHeight={headerHeight}
            className={classes.table}
            {...tableProps}
            rowClassName={this.getRowClassName}
          >
            {columns.map(({ dataKey, ...other }, index) => {
              return (
                <Column
                  key={dataKey}
                  headerRenderer={(headerProps) =>
                    this.headerRenderer({
                      ...headerProps,
                      columnIndex: index,
                    })
                  }
                  className={classes.flexContainer}
                  cellRenderer={this.cellRenderer}
                  dataKey={dataKey}
                  {...other}
                />
              );
            })}
          </Table>
        )}
      </AutoSizer>
    );
  }
}

MuiVirtualizedTable.propTypes = {
  classes: PropTypes.object.isRequired,
  columns: PropTypes.arrayOf(
    PropTypes.shape({
      dataKey: PropTypes.string.isRequired,
      label: PropTypes.string.isRequired,
      numeric: PropTypes.bool,
      width: PropTypes.number.isRequired,
    }),
  ).isRequired,
  headerHeight: PropTypes.number,
  onRowClick: PropTypes.func,
  rowHeight: PropTypes.number,
};

const defaultTheme = createTheme();
const VirtualizedTable = withStyles(styles, { defaultTheme })(MuiVirtualizedTable);

export default function ReactVirtualizedTable( {emulator_data} ) {
  
  const rows = useMemo(
    () => {
      let temp = new Array(0)
      for(let i=0; i<emulator_data.MEMORY.length; i++){
        if(i%16 === 0){
          temp.push({
            addr: decToHex(Object.keys(emulator_data.MEMORY[i])[0]),
            value1: decToHex(Object.values(emulator_data.MEMORY[i])[0]),
            value2: decToHex(Object.values(emulator_data.MEMORY[i+1])[0]),
            value3: decToHex(Object.values(emulator_data.MEMORY[i+2])[0]),
            value4: decToHex(Object.values(emulator_data.MEMORY[i+3])[0]),
            value5: decToHex(Object.values(emulator_data.MEMORY[i+4])[0]),
            value6: decToHex(Object.values(emulator_data.MEMORY[i+5])[0]),
            value7: decToHex(Object.values(emulator_data.MEMORY[i+6])[0]),
            value8: decToHex(Object.values(emulator_data.MEMORY[i+7])[0]),
            value9: decToHex(Object.values(emulator_data.MEMORY[i+8])[0]),
            value10: decToHex(Object.values(emulator_data.MEMORY[i+9])[0]),
            value11: decToHex(Object.values(emulator_data.MEMORY[i+10])[0]),
            value12: decToHex(Object.values(emulator_data.MEMORY[i+11])[0]),
            value13: decToHex(Object.values(emulator_data.MEMORY[i+12])[0]),
            value14: decToHex(Object.values(emulator_data.MEMORY[i+13])[0]),
            value15: decToHex(Object.values(emulator_data.MEMORY[i+14])[0]),
            value16: decToHex(Object.values(emulator_data.MEMORY[i+15])[0]),
          })
        }
      }
      return temp
    },
    [emulator_data]
  )
  
  return (
    <Paper style={{ height: '100%', width: '100%', position: 'relative' }}>
      <VirtualizedTable
        rowCount={rows.length}
        rowGetter={({ index }) => rows[index]}
        columns={[
          {
            dataKey: 'addr',
          },
          {
            dataKey: 'value1',
          },
          {
            dataKey: 'value2',
          },
          {
            dataKey: 'value3',
          },
          {
            dataKey: 'value4',
          },
          {
            dataKey: 'value5',
          },
          {
            dataKey: 'value6',
          },
          {
            dataKey: 'value7',
          },
          {
            dataKey: 'value8',
          },
          {
            dataKey: 'value9',
          },
          {
            dataKey: 'value10',
          },
          {
            dataKey: 'value11',
          },
          {
            dataKey: 'value12',
          },
          {
            dataKey: 'value13',
          },
          {
            dataKey: 'value14',
          },
          {
            dataKey: 'value15',
          },
          {
            dataKey: 'value16',
          },
        ]}
      />
    </Paper>
  );
}
