import { Card, CardContent, Typography } from '@mui/material';
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

export default function ConfidenceChart({ result }) {
  // The model reports confidence for its predicted label. With two classes,
  // the other class gets whatever is left over, so the slices add up to 100%.
  const phishing = result.label === 'phishing' ? result.confidence : 1 - result.confidence;
  const phishingPct = Math.round(phishing * 100);
  const legitimatePct = 100 - phishingPct;

  const data = [
    { name: 'Phishing', percent: phishingPct, colour: '#c62828' },
    { name: 'Legitimate', percent: legitimatePct, colour: '#2e7d32' },
  ];

  return (
    <Card variant="outlined" sx={{ mt: 3 }}>
      <CardContent>
        <Typography variant="h2" component="h2" gutterBottom>
          How sure is the model?
        </Typography>

        {/* Text version of the chart, for screen readers. */}
        <Typography sx={{ position: 'absolute', left: -9999 }}>
          Phishing {phishingPct} percent, legitimate {legitimatePct} percent.
        </Typography>

        <div style={{ width: '100%', height: 300 }} aria-hidden="true">
          <ResponsiveContainer>
            <PieChart>
              <Pie
                data={data}
                dataKey="percent"
                nameKey="name"
                innerRadius={60}      // remove this line for a full pie
                outerRadius={95}
                paddingAngle={2}
                // Hide the label on an empty (0%) slice.
                label={({ value }) => (value > 0 ? `${value}%` : '')}
              >
                {data.map((d) => <Cell key={d.name} fill={d.colour} />)}
              </Pie>
              <Tooltip formatter={(value) => `${value}%`} />
              <Legend verticalAlign="bottom" />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
