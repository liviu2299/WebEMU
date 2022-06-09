import { styled } from '@mui/material/styles';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';

export const EditorContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '90vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3'
}));
export const RegsContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '50vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem'
}));
export const FlagsContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '50vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem'
}));
export const LogContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '50vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem'
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
  color: theme.palette.text.primary,
  height: '30vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem'
}));
export const MemoryContainer = styled(Paper)(({ theme }) => ({
  ...theme.typography.body2,
  color: theme.palette.text.primary,
  height: '39vh',
  position: 'relative',
  border: 'solid 1px',
  borderColor: '#F3F3F3',
  padding: '0.5rem'
}));
export const NavbarContainer = styled(Paper)(({ theme }) => ({
  borderBottom: 'solid 2px',
  borderColor: '#F3F3F3',
}));
export const BoxContainer = styled(Box)(({ theme }) => ({
  backgroundColor: '#303030',
  height: '100%'
}));