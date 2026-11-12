import { useState } from 'react';
import {
  Box, Card, CardContent, Typography, Rating, TextField, Button, Paper, Alert,
} from '@mui/material';

// Limits keep reviews short. A real back end would enforce them too.
const MAX_NAME = 40;
const MAX_TEXT = 500;
const STORAGE_KEY = 'user_reviews';

// Sample content for the demo.
const SAMPLE_REVIEWS = [
  { id: 's1', name: 'Alex T.', role: 'Student', rating: 5,
    text: 'Quick and easy to use. I pasted a suspicious link and got a clear answer straight away.' },
  { id: 's2', name: 'Priya S.', role: 'IT administrator', rating: 4,
    text: 'The confidence chart helps me judge how much to trust each result.' },
  { id: 's3', name: 'Sam L.', role: 'Small business owner', rating: 5,
    text: 'Simple layout, and it works well on my phone.' },
];

// Browser storage can be blocked or empty, so every access is wrapped in try/catch.
function loadSaved() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
    return Array.isArray(saved) ? saved : [];
  } catch {
    return [];
  }
}

export default function Reviews() {
  const [userReviews, setUserReviews] = useState(loadSaved);
  const [name, setName] = useState('');
  const [text, setText] = useState('');
  const [rating, setRating] = useState(0);
  const [errors, setErrors] = useState({});
  const [thanks, setThanks] = useState(false);

  const handleSubmit = (event) => {
    event.preventDefault();
    const trimmedText = text.trim();

    const newErrors = {};
    if (!rating) newErrors.rating = 'Please choose a star rating.';
    if (!trimmedText) newErrors.text = 'Please write a short review.';

    setErrors(newErrors);
    setThanks(false);
    if (Object.keys(newErrors).length > 0) return;

    const review = {
      id: `u${Date.now()}`,
      name: name.trim() || 'Anonymous',
      role: 'Visitor',
      rating,
      text: trimmedText,
    };
    const updated = [review, ...userReviews]; // newest first
    setUserReviews(updated);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch {
      // Storage unavailable: the review still shows for this session.
    }
    setName('');
    setText('');
    setRating(0);
    setThanks(true);
  };

  const allReviews = [...userReviews, ...SAMPLE_REVIEWS];

  return (
    <Box component="section" aria-labelledby="reviews-heading" sx={{ mt: 8 }}>
      <Typography id="reviews-heading" variant="h2" component="h2" gutterBottom>
        What people say
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Reviews from users
      </Typography>

      {/* Three columns on desktop, one on a phone. */}
      <Box sx={{ display: 'grid', gap: 2,
                 gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
        {allReviews.map((review) => (
          <Card key={review.id} variant="outlined">
            <CardContent>
              <Rating value={review.rating} readOnly
                      aria-label={`${review.rating} out of 5 stars`} />
              {/* React prints this as plain text, never as HTML. */}
              <Typography sx={{ mt: 1, mb: 2, wordBreak: 'break-word' }}>
                “{review.text}”
              </Typography>
              <Typography variant="subtitle2">{review.name}</Typography>
              <Typography variant="body2" color="text.secondary">{review.role}</Typography>
            </CardContent>
          </Card>
        ))}
      </Box>

      <Paper variant="outlined" sx={{ mt: 4, p: { xs: 2, sm: 3 } }}>
        <Typography variant="h2" component="h3" gutterBottom>
          Add your review
        </Typography>

        <Box component="form" onSubmit={handleSubmit} noValidate
             sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TextField
            label="Your name (optional)"
            value={name}
            onChange={(e) => setName(e.target.value)}
            inputProps={{ maxLength: MAX_NAME }}
          />

          <Box>
            <Typography component="legend" variant="body2">Your rating</Typography>
            <Rating
              name="rating"
              value={rating}
              onChange={(e, value) => setRating(value || 0)}
            />
            {errors.rating && (
              <Typography variant="caption" color="error" display="block">
                {errors.rating}
              </Typography>
            )}
          </Box>

          <TextField
            label="Your review"
            value={text}
            onChange={(e) => setText(e.target.value)}
            multiline
            minRows={3}
            inputProps={{ maxLength: MAX_TEXT }}
            error={Boolean(errors.text)}
            helperText={errors.text || `${text.length}/${MAX_TEXT} characters`}
          />

          <Button type="submit" variant="contained" sx={{ alignSelf: 'flex-start' }}>
            Submit review
          </Button>

          <div aria-live="polite">
            {thanks && <Alert severity="success">Thank you for your review.</Alert>}
          </div>
        </Box>
      </Paper>
    </Box>
  );
}