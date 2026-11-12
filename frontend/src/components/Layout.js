import { AppBar, Toolbar, Typography, Box, Link } from '@mui/material';
import ShieldIcon from '@mui/icons-material/Shield';
import { Link as RouterLink, Outlet } from 'react-router-dom';
import { COMPANY_NAME, APP_NAME, CONTACT_EMAIL, CONTACT_PHONE } from '../config';

// Header and footer appear on every page, including the 404 page.
export default function Layout() {
  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Sticky: stays at the top while the page scrolls. */}
      <AppBar position="sticky" elevation={2}>
        <Toolbar>
          <Box
            component={RouterLink}
            to="/"
            onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
            aria-label={`${COMPANY_NAME} home`}
            sx={{ display: 'flex', alignItems: 'center', color: 'inherit',
                  textDecoration: 'none' }}
          >
            <ShieldIcon sx={{ mr: 1 }} />
            <Typography variant="h6" component="span" noWrap sx={{ fontWeight: 700 }}>
              {COMPANY_NAME}
              <Box component="span"
                   sx={{ display: { xs: 'none', sm: 'inline' }, fontWeight: 400 }}>
                {' | '}{APP_NAME}
              </Box>
            </Typography>
          </Box>
        </Toolbar>
      </AppBar>

      {/* Each page supplies its own <main>, so none is added here. */}
      <Box sx={{ flex: 1 }}>
        <Outlet />
      </Box>

      <Box
        component="footer"
        sx={{ py: 3, px: 2, textAlign: 'center', bgcolor: 'background.paper',
              borderTop: 1, borderColor: 'divider' }}
      >
        <Typography variant="body2">
          Email: <Link href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</Link>
          {' \u00A0|\u00A0 '}
          Phone: <Link href={`tel:${CONTACT_PHONE.replace(/[^\d+]/g, '')}`}>{CONTACT_PHONE}</Link>
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          © {new Date().getFullYear()} {COMPANY_NAME}. Predictions are estimates and can be wrong.
        </Typography>
      </Box>
    </Box>
  );
}