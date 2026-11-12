import { useState } from 'react';
import { Container, Typography, Alert, Paper } from '@mui/material';
import UrlForm from '../components/UrlForm';
import ResultCard from '../components/ResultCard';
import ConfidenceChart from '../components/ConfidenceChart';
import HistoryPanel from '../components/HistoryPanel';
import Reviews from '../components/Reviews';
import { checkUrl } from '../api';

//main page

export default function Home() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  // Every URL checked in this session, kept for the history chart.
  const [history, setHistory] = useState([]);

  const handleCheck = async (url) => {
    setLoading(true);
    setResult(null);
    setError('');
    try {
      const data = await checkUrl(url);
      setResult(data);
      // Keep the 20 most recent checks so the chart stays readable.
      setHistory((previous) => {
        const nextId = previous.length ? previous[previous.length - 1].id + 1 : 1;
        return [...previous, { id: nextId, ...data }].slice(-20);
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container component="main" maxWidth="md" sx={{ mt: 6, mb: 8 }}>
      <Typography variant="h1" gutterBottom>Is this link safe?</Typography>
      <Typography sx={{ mb: 4 }} color="text.secondary">
        Paste a URL and our model will estimate whether it is phishing or legitimate.
      </Typography>

      <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 } }}>
        <UrlForm onSubmit={handleCheck} loading={loading} />
      </Paper>

      {/* aria-live makes screen readers announce the result when it appears */}
      <div aria-live="polite">
        {error && <Alert severity="error" sx={{ mt: 3 }}>{error}</Alert>}
        {result && <ResultCard result={result} />}
      </div>

      {result && <ConfidenceChart result={result} />}

      {history.length > 0 && (
        <HistoryPanel history={history} onClear={() => setHistory([])} />
      )}

      <Reviews />
    </Container>
  );
}