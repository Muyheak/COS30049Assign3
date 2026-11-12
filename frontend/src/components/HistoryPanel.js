import { useState } from 'react';
import {
  Card, CardContent, Typography, ToggleButton, ToggleButtonGroup, Button,
  List, ListItemButton, ListItemText, Paper, Box, Chip,
} from '@mui/material';
import {
  ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, Cell,
  ReferenceArea, ReferenceLine, ResponsiveContainer,
} from 'recharts';

const RED = '#c62828';
const GREEN = '#2e7d32';

export default function HistoryPanel({ history, onClear }) {
  const [filter, setFilter] = useState('all');
  const [selectedId, setSelectedId] = useState(null);

  // Put every check on the same scale: the probability that the URL is phishing.
  const entries = history.map((item) => {
    const phishing = item.label === 'phishing' ? item.confidence : 1 - item.confidence;
    return { ...item, phishingPct: Math.round(phishing * 100) };
  });

  const phishingCount = entries.filter((e) => e.label === 'phishing').length;
  const legitimateCount = entries.length - phishingCount;

  const visible = entries.filter((e) => filter === 'all' || e.label === filter);
  const selected = visible.find((e) => e.id === selectedId) || null;

  return (
    <Card variant="outlined" sx={{ mt: 3 }}>
      <CardContent>
        <Typography variant="h2" component="h2" gutterBottom>
          How do my checks compare?
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Each dot is one URL checked in this session. Dots in the red zone were
          judged likely phishing. Click a dot or a list item to see its details.
        </Typography>

        {/* Summary counts */}
        <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
          <Chip label={`${entries.length} checked`} />
          <Chip label={`${phishingCount} phishing`}
                sx={{ bgcolor: RED, color: 'common.white' }} />
          <Chip label={`${legitimateCount} legitimate`}
                sx={{ bgcolor: GREEN, color: 'common.white' }} />
        </Box>

        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, alignItems: 'center', mb: 2 }}>
          <ToggleButtonGroup
            exclusive
            size="small"
            value={filter}
            onChange={(e, value) => value && setFilter(value)}
            aria-label="Filter checks by result"
          >
            <ToggleButton value="all">All</ToggleButton>
            <ToggleButton value="phishing">Phishing</ToggleButton>
            <ToggleButton value="legitimate">Legitimate</ToggleButton>
          </ToggleButtonGroup>
          <Button size="small" onClick={() => { onClear(); setSelectedId(null); }}>
            Clear history
          </Button>
        </Box>

        {visible.length === 0 ? (
          <Typography sx={{ py: 4 }}>No checks match this filter.</Typography>
        ) : (
          <>
            {/* The list below is the keyboard and screen-reader version of the chart. */}
            <div style={{ width: '100%', height: 300 }} aria-hidden="true">
              <ResponsiveContainer>
                <ScatterChart margin={{ top: 10, right: 16, left: 8, bottom: 28 }}>
                  {/* Shaded zones: below 50% the model leans legitimate, above it phishing. */}
                  <ReferenceArea y1={0} y2={50} fill={GREEN} fillOpacity={0.1}
                    label={{ value: 'Likely legitimate', position: 'insideBottomLeft', fontSize: 12 }} />
                  <ReferenceArea y1={50} y2={100} fill={RED} fillOpacity={0.1}
                    label={{ value: 'Likely phishing', position: 'insideTopLeft', fontSize: 12 }} />
                  <ReferenceLine y={50} stroke="#555" strokeDasharray="4 4" />

                  <XAxis type="number" dataKey="id" allowDecimals={false}
                         domain={['dataMin - 1', 'dataMax + 1']}
                         label={{ value: 'Check number', position: 'insideBottom', offset: -16 }} />
                  <YAxis type="number" dataKey="phishingPct" domain={[0, 100]} unit="%"
                         label={{ value: 'Phishing probability', angle: -90, position: 'insideLeft' }} />
                  <ZAxis range={[140, 140]} />

                  <Tooltip
                    cursor={{ strokeDasharray: '3 3' }}
                    content={({ active, payload }) =>
                      active && payload?.length ? (
                        <Paper variant="outlined" sx={{ p: 1, maxWidth: 260 }}>
                          {/* React prints this as plain text, never as a link. */}
                          <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                            {payload[0].payload.url}
                          </Typography>
                          <Typography variant="body2">
                            Phishing probability: {payload[0].payload.phishingPct}%
                          </Typography>
                        </Paper>
                      ) : null
                    }
                  />

                  <Scatter data={visible} cursor="pointer"
                           onClick={(point) => setSelectedId(point?.payload?.id ?? point?.id)}>
                    {visible.map((e) => (
                      <Cell key={e.id}
                            fill={e.label === 'phishing' ? RED : GREEN}
                            stroke={e.id === selectedId ? '#000' : '#fff'}
                            strokeWidth={e.id === selectedId ? 3 : 1} />
                    ))}
                  </Scatter>
                </ScatterChart>
              </ResponsiveContainer>
            </div>

            {selected && (
              <Paper variant="outlined" sx={{ p: 2, mt: 2 }} aria-live="polite">
                <Typography variant="subtitle2">Selected check #{selected.id}</Typography>
                <Typography sx={{ wordBreak: 'break-all' }}>{selected.url}</Typography>
                <Typography sx={{ fontWeight: 700,
                                  color: selected.label === 'phishing' ? RED : GREEN }}>
                  {selected.label === 'phishing' ? 'Phishing' : 'Legitimate'}
                  {' '}({Math.round(selected.confidence * 100)}% confidence)
                </Typography>
              </Paper>
            )}

            {/* Newest first. */}
            <List dense sx={{ mt: 1 }} aria-label="Checked URLs">
              {[...visible].reverse().map((e) => (
                <ListItemButton key={e.id} selected={e.id === selectedId}
                                onClick={() => setSelectedId(e.id)}>
                  <ListItemText
                    primary={e.url}
                    secondary={`#${e.id} · ${e.label} · ${Math.round(e.confidence * 100)}%`}
                    primaryTypographyProps={{ sx: { wordBreak: 'break-all' } }}
                  />
                </ListItemButton>
              ))}
            </List>
          </>
        )}
      </CardContent>
    </Card>
  );
}