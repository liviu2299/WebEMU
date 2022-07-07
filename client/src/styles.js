import { styled } from '@mui/material/styles';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import { createTheme } from '@mui/material/styles';

export const theme = createTheme({
  palette: {
    type: 'dark',
    primary: {
      main: '#263238',
      contrastText: '#fff',
    },
    secondary: {
      main: '#4B75B7',
      contrastText: "#fff",
    },
    background: {
      default: '#303030',
      paper: '#263238',
    },
    text: {
    primary: '#F3F3F3',
    },
  },
  typography: {
    fontFamily: 'Roboto Mono',
  }
});

export const EditorContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '90vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
}));
export const RegsContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '52vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem',
}));
export const FlagsContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '52vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem',
}));
export const LogContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '52vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem',
  fontFamily: 'Roboto Mono',
  fontSize: 13
}));
export const MappingContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '20vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem'
}));
export const StackContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: "theme.palette.text.primary",
  height: '32vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem'
}));
export const MemoryContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '37vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem',
  fontFamily: 'Roboto Mono'
}));
export const NavbarContainer = styled(Paper)(({ theme }) => ({
  borderBottom: 'solid 2px',
  borderColor: '#F3F3F3',
}));
export const BoxContainer = styled(Box)(({ theme }) => ({
  backgroundColor: '#303030',
  height: '100%'
}));