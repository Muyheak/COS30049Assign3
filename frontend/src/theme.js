import { createTheme } from '@mui/material/styles';

// One theme for the whole app: colours, fonts and shapes are defined here only.
const theme = createTheme({
  palette: {
    primary: { main: '#1a4fd6' },
    error: { main: '#c62828' },
    success: { main: '#2e7d32' },
    background: { default: '#e8eefc', paper: '#ffffff' },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h1: { fontSize: '2.25rem', fontWeight: 700 },
    h2: { fontSize: '1.5rem', fontWeight: 600 },
  },
  shape: { borderRadius: 12 },
  components: {
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: { root: { textTransform: 'none', fontWeight: 600 } },
    },
  },
});

export default theme;