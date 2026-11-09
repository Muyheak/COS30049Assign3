import { Card, CardContent, Typography, Box } from '@mui/material';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

export default function ResultCard({ result }) {
  const isPhishing = result.label === 'phishing';
  const colour = isPhishing ? 'error.main' : 'success.main';
  const percent = Math.round(result.confidence * 100);

  return (
    <Card variant="outlined" sx={{ mt: 4, borderColor: colour, borderWidth: 2 }}>
      <CardContent>
        {/* The result is the biggest element on the screen. */}
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, color: colour }}>
          {isPhishing
            ? <WarningAmberIcon sx={{ fontSize: 56 }} />
            : <CheckCircleIcon sx={{ fontSize: 56 }} />}
          <Typography variant="h1" component="p">
            {isPhishing ? 'Phishing' : 'Legitimate'}
          </Typography>
        </Box>
        <Typography variant="h2" component="p" sx={{ mt: 1 }}>
          Confidence: {percent}%
        </Typography>
        {/* Shown as plain text, never as a link. */}
        <Typography sx={{ mt: 2, wordBreak: 'break-all' }}>
          URL checked: {result.url}
        </Typography>
      </CardContent>
    </Card>
  );
}