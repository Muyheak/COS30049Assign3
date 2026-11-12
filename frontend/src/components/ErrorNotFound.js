import { Component } from 'react';
import { Container, Typography, Button } from '@mui/material';

// Error boundaries must be class components: React has no hook for this.
export default class ErrorBoundary extends Component {
  state = { hasError: false };

  // React calls this when any child component crashes while rendering.
  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <Container component="main" role="alert" sx={{ mt: 8, textAlign: 'center' }}>
          <Typography variant="h1" gutterBottom>Something went wrong</Typography>
          <Typography sx={{ mb: 3 }}>
            An unexpected error occurred. Your data has not been affected.
          </Typography>
          {/* A full reload resets the app to a clean state. */}
          <Button variant="contained" onClick={() => window.location.assign('/')}>
            Reload the app
          </Button>
        </Container>
      );
    }
    return this.props.children;
  }
}