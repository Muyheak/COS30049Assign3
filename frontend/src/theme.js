import { createTheme } from '@mui/material/styles';

// One theme for the whole app: every colour, font and corner radius
// is defined here so the design stays consistent.
const theme = createTheme({
  palette: {
    primary: { main: '#1a4fd6' },   // buttons, links, focus
    error: { main: '#c62828' },     // phishing results, error messages
    success: { main: '#2e7d32' },   // legitimate results
    background: { default: '#f5f7fb' },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h1: { fontSize: '2.25rem', fontWeight: 700 },
    h2: { fontSize: '1.5rem', fontWeight: 600 },
  },
  shape: { borderRadius: 12 },
});

export default theme;