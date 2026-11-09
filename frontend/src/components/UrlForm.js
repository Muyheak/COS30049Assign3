import { useState } from 'react';
import { Box, TextField, Button, CircularProgress } from '@mui/material';

// Must match the limit enforced by the back end.
const MAX_URL_LENGTH = 2048;

// Returns an error message, or '' if the input is acceptable.
function validate(value) {
  if (!value) return 'Please enter a URL.';
  if (value.length > MAX_URL_LENGTH) {
    return `URL is too long (maximum ${MAX_URL_LENGTH} characters).`;
  }
  if (/\s/.test(value)) return 'A URL cannot contain spaces.';
  return '';
}

export default function UrlForm({ onSubmit, loading }) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (event) => {
    event.preventDefault();          // stop the browser reloading the page
    const trimmed = value.trim();
    const message = validate(trimmed);
    setError(message);
    if (!message) onSubmit(trimmed); // only send valid input to the parent
  };

  return (
    <Box component="form" onSubmit={handleSubmit} noValidate
         sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
      <TextField
        label="URL to check"
        placeholder="http://example.com/login"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        error={Boolean(error)}
        helperText={error || 'Paste the full link you want to check.'}
        sx={{ flex: '1 1 300px' }}
      />
      <Button type="submit" variant="contained" disabled={loading}
              sx={{ minWidth: 140, height: 56 }}>
        {loading ? <CircularProgress size={24} /> : 'Check URL'}
      </Button>
    </Box>
  );
}