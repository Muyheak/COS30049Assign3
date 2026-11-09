import { useState } from 'react';
import { Container, Typography, Alert } from '@mui/material';
import UrlForm from '../components/UrlForm';
import ResultCard from '../components/ResultCard';
import { checkUrl } from '../api';

export default function Home() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleCheck = async (url) => {
    setLoading(true);
    setResult(null);
    setError('');
    try {
      setResult(await checkUrl(url));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container component="main" sx={{ mt: 8 }}>
      <Typography variant="h1" gutterBottom>Phishing URL Checker</Typography>
      <UrlForm onSubmit={handleCheck} loading={loading} />

      {/* aria-live makes screen readers announce the result when it appears */}
      <div aria-live="polite">
        {error && <Alert severity="error" sx={{ mt: 3 }}>{error}</Alert>}
        {result && <ResultCard result={result} />}
      </div>
    </Container>
  );
}