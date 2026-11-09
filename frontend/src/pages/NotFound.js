import { Container, Typography, Button } from '@mui/material';
import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <Container component="main" sx={{ mt: 8, textAlign: 'center' }}>
      <Typography variant="h1" gutterBottom>404</Typography>
      <Typography variant="h2" gutterBottom>Page not found</Typography>
      <Typography sx={{ mb: 3 }}>
        The address you entered does not exist.
      </Typography>
      <Button variant="contained" component={Link} to="/">
        Back to home
      </Button>
    </Container>
  );
}