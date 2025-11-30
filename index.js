require('dotenv').config({ quiet: true });
const path = require('path');
const express = require('express');
const session = require('express-session');
const methodOverride = require('method-override');
const morgan = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { db, initDb } = require('./server/db');
const expressLayouts = require('express-ejs-layouts');
const { sendVerificationEmail } = require('./server/mailer');

const app = express();

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_change_me';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(expressLayouts);
app.set('layout', 'layout');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(morgan('dev'));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, { id: user.id, email: user.email, role: user.role, name: user.name });
});
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(
  new LocalStrategy(
    { usernameField: 'email', passwordField: 'password' },
    (email, password, done) => {
      const normEmail = email.toLowerCase();
      db.get('SELECT * FROM users WHERE email = ?', [normEmail], async (err, user) => {
        if (err) return done(err);
        if (!user || !user.password_hash) return done(null, false, { message: 'Invalid credentials' });
        if (user.banned) return done(null, false, { message: 'Account is banned' });
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return done(null, false, { message: 'Invalid credentials' });
        if (!user.email_verified) return done(null, false, { reason: 'unverified', email: normEmail });
        return done(null, user);
      });
    }
  )
);

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL,
      },
      (accessToken, refreshToken, profile, done) => {
        try {
          const googleId = profile.id;
          const rawEmail = (profile.emails && profile.emails[0] && profile.emails[0].value) || null;
          const email = rawEmail ? rawEmail.toLowerCase() : null;
          const name = profile.displayName || (profile.name ? `${profile.name.givenName || ''} ${profile.name.familyName || ''}`.trim() : (email || 'Google User'));
          db.get('SELECT * FROM users WHERE google_id = ? OR (email IS NOT NULL AND email = ?)', [googleId, email], (err, user) => {
            if (err) return done(err);
            if (user) {
              if (user.banned) return done(null, false, { message: 'Account is banned' });
              if (!user.google_id) {
                db.run('UPDATE users SET google_id = ?, email_verified = 1 WHERE id = ?', [googleId, user.id], (uErr) => done(uErr, { ...user, google_id: googleId, email_verified: 1 }));
              } else {
                if (!user.email_verified) {
                  db.run('UPDATE users SET email_verified = 1 WHERE id = ?', [user.id], (uErr) => done(uErr, { ...user, email_verified: 1 }));
                } else {
                  return done(null, user);
                }
              }
            } else {
              db.run(
                'INSERT INTO users (email, name, google_id, role, email_verified, created_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
                [email, name, googleId, 'user', 1],
                function (insErr) {
                  if (insErr) return done(insErr);
                  db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (selErr, newUser) => done(selErr, newUser));
                }
              );
            }
          });
        } catch (e) {
          return done(e);
        }
      }
    )
  );
}

function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) {
    db.get('SELECT banned FROM users WHERE id = ?', [req.user.id], (e, row) => {
      if (e || !row) return res.redirect('/logout');
      if (row.banned) {
        req.logout(() => {
          req.session.message = 'Your account has been banned.';
          return res.redirect('/login');
        });
      } else {
        return next();
      }
    });
    return;
  }
  res.redirect('/login');
}
function ensureAdmin(req, res, next) {
  if (!req.isAuthenticated()) return res.status(403).send('Forbidden');
  db.get('SELECT role, banned FROM users WHERE id = ?', [req.user.id], (e, row) => {
    if (e || !row) return res.status(403).send('Forbidden');
    if (row.banned) {
      req.logout(() => {
        req.session.message = 'Your account has been banned.';
        return res.redirect('/login');
      });
      return;
    }
    if (row.role === 'admin') return next();
    return res.status(403).send('Forbidden');
  });
}

app.use((req, res, next) => {
  res.locals.currentUser = req.user || null;
  res.locals.googleEnabled = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);
  res.locals.message = req.session.message || null;
  delete req.session.message;
  next();
});

app.get('/', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login', { query: req.query }));
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      if (info && info.reason === 'unverified' && info.email) {
        return res.redirect(`/login?unverified=1&email=${encodeURIComponent(info.email)}`);
      }
      return res.redirect('/login?error=1');
    }
    req.logIn(user, (e) => {
      if (e) return next(e);
      return res.redirect('/dashboard');
    });
  })(req, res, next);
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) {
    req.session.message = 'Email and password are required';
    return res.redirect('/register');
  }
  const hash = await bcrypt.hash(password, 10);
  const normEmail = email.toLowerCase();
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  db.run(
    'INSERT INTO users (name, email, password_hash, role, email_verified, verify_token, verify_token_expires, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
    [name || '', normEmail, hash, 'user', 0, token, expires],
    async function (err) {
      if (err) {
        req.session.message = 'Registration failed. Email may be already in use.';
        return res.redirect('/register');
      }
      try { await sendVerificationEmail(normEmail, token, name || ''); } catch (e) { console.error('Failed to send verification email:', e.message); }
      req.session.message = 'Registration successful. Please check your email to verify your account.';
      res.redirect('/login');
    }
  );
});

app.post('/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/login');
  });
});

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login?oauth_error=1' }), (req, res) => {
    res.redirect('/dashboard');
  });
}

app.get('/dashboard', ensureAuth, (req, res) => {
  db.all(
    'SELECT * FROM tickets WHERE user_id = ? ORDER BY updated_at DESC, created_at DESC',
    [req.user.id],
    (err, rows) => {
      if (err) rows = [];
      res.render('dashboard', { tickets: rows });
    }
  );
});

app.get('/tickets/new', ensureAuth, (req, res) => res.render('ticket_new'));
app.post('/tickets', ensureAuth, (req, res) => {
  const { subject, description } = req.body;
  if (!subject || !description) {
    req.session.message = 'Subject and description are required.';
    return res.redirect('/tickets/new');
  }
  db.run(
    'INSERT INTO tickets (user_id, subject, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)',
    [req.user.id, subject, description, 'open'],
    function (err) {
      if (err) {
        req.session.message = 'Failed to create ticket.';
        return res.redirect('/tickets/new');
      }
      res.redirect(`/tickets/${this.lastID}`);
    }
  );
});

app.get('/tickets/:id', ensureAuth, (req, res) => {
  const id = req.params.id;
  db.get('SELECT t.*, u.name as user_name, u.email as user_email FROM tickets t JOIN users u ON u.id = t.user_id WHERE t.id = ?', [id], (err, ticket) => {
    if (err || !ticket) return res.status(404).send('Not found');
    if (req.user.role !== 'admin' && ticket.user_id !== req.user.id) return res.status(403).send('Forbidden');
    db.all('SELECT r.*, u.name, u.email FROM ticket_responses r JOIN users u ON u.id = r.user_id WHERE r.ticket_id = ? ORDER BY r.created_at ASC', [id], (rErr, responses) => {
      if (rErr) responses = [];
      res.render('ticket_view', { ticket, responses });
    });
  });
});

app.post('/tickets/:id/respond', ensureAuth, (req, res) => {
  const id = req.params.id;
  const { message } = req.body;
  if (!message) return res.redirect(`/tickets/${id}`);
  db.get('SELECT * FROM tickets WHERE id = ?', [id], (err, ticket) => {
    if (err || !ticket) return res.status(404).send('Not found');
    if (req.user.role !== 'admin' && ticket.user_id !== req.user.id) return res.status(403).send('Forbidden');
    db.run(
      'INSERT INTO ticket_responses (ticket_id, user_id, message, is_admin_response, created_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)',
      [id, req.user.id, message, req.user.role === 'admin' ? 1 : 0],
      function (rErr) {
        if (rErr) return res.status(500).send('Failed to add response');
        db.run('UPDATE tickets SET updated_at = CURRENT_TIMESTAMP, status = ? WHERE id = ?', [req.user.role === 'admin' ? 'answered' : 'open', id], () => {
          res.redirect(`/tickets/${id}`);
        });
      }
    );
  });
});

app.get('/admin', ensureAdmin, (req, res) => {
  const status = req.query.status;
  const params = [];
  let sql = 'SELECT t.*, u.email as user_email, u.name as user_name FROM tickets t JOIN users u ON u.id = t.user_id';
  if (status) {
    sql += ' WHERE t.status = ?';
    params.push(status);
  }
  sql += ' ORDER BY updated_at DESC, created_at DESC';
  db.all(sql, params, (err, rows) => {
    if (err) rows = [];
    res.render('admin', { tickets: rows, status: status || '' });
  });
});

app.post('/admin/tickets/:id/status', ensureAdmin, (req, res) => {
  const { status } = req.body;
  const id = req.params.id;
  db.run('UPDATE tickets SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [status, id], (err) => {
    if (err) req.session.message = 'Failed to update status';
    res.redirect('/admin');
  });
});

app.post('/admin/tickets/:id/delete', ensureAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM tickets WHERE id = ?', [id], (err) => {
    req.session.message = err ? 'Failed to delete ticket.' : 'Ticket deleted.';
    res.redirect('/admin');
  });
});

app.get('/admin/users', ensureAdmin, (req, res) => {
  db.all(
    `SELECT 
        id, name, email, role, created_at, banned, email_verified,
        CASE WHEN google_id IS NOT NULL AND TRIM(google_id) <> '' THEN 1 ELSE 0 END AS has_google,
        CASE WHEN password_hash IS NOT NULL AND TRIM(password_hash) <> '' THEN 1 ELSE 0 END AS has_password
      FROM users
      ORDER BY created_at DESC, id DESC`,
    [],
    (err, users) => {
      if (err) users = [];
      res.render('admin_users', { users });
    }
  );
});

app.post('/admin/users/:id/make-admin', ensureAdmin, (req, res) => {
  const id = req.params.id;
  db.run('UPDATE users SET role = ? WHERE id = ?', ['admin', id], (err) => {
    req.session.message = err ? 'Failed to grant admin rights.' : 'Admin rights granted.';
    res.redirect('/admin/users');
  });
});

app.post('/admin/users/:id/unadmin', ensureAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) {
    req.session.message = 'Invalid user id.';
    return res.redirect('/admin/users');
  }
  if (req.user && req.user.id === id) {
    req.session.message = 'You cannot remove your own admin role.';
    return res.redirect('/admin/users');
  }
  db.get('SELECT COUNT(*) AS cnt FROM users WHERE role = ?', ['admin'], (err, row) => {
    if (err) {
      req.session.message = 'Database error.';
      return res.redirect('/admin/users');
    }
    const adminCount = row ? row.cnt : 0;
    db.get('SELECT id, email, role FROM users WHERE id = ?', [id], (e2, user) => {
      if (e2 || !user) {
        req.session.message = 'User not found.';
        return res.redirect('/admin/users');
      }
      if (user.role !== 'admin') {
        req.session.message = 'User is not an admin.';
        return res.redirect('/admin/users');
      }
      if (adminCount <= 1) {
        req.session.message = 'Cannot remove the last admin.';
        return res.redirect('/admin/users');
      }
      db.run('UPDATE users SET role = ? WHERE id = ?', ['user', id], (uErr) => {
        req.session.message = uErr ? 'Failed to remove admin rights.' : `Admin rights removed from ${user.email || 'user'}.`;
        return res.redirect('/admin/users');
      });
    });
    });
    });

    app.post('/admin/users/grant-admin', ensureAdmin, (req, res) => {
  let { email, name } = req.body;
  email = (email || '').trim().toLowerCase();
  name = (name || '').trim();
  if (!email) {
    req.session.message = 'Email is required.';
    return res.redirect('/admin/users');
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      req.session.message = 'Database error.';
      return res.redirect('/admin/users');
    }
    if (user) {
      db.run('UPDATE users SET role = ? WHERE id = ?', ['admin', user.id], (uErr) => {
        req.session.message = uErr ? 'Failed to grant admin rights.' : `Admin rights granted to ${email}.`;
        return res.redirect('/admin/users');
      });
    } else {
      db.run(
        'INSERT INTO users (name, email, role, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
        [name, email, 'admin'],
        (iErr) => {
          req.session.message = iErr ? 'Failed to create admin user.' : `Admin user created for ${email}.`;
          return res.redirect('/admin/users');
        }
      );
    }
  });
});

app.post('/admin/users/:id/ban', ensureAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) { req.session.message = 'Invalid user id.'; return res.redirect('/admin/users'); }
  if (req.user && req.user.id === id) { req.session.message = 'You cannot ban yourself.'; return res.redirect('/admin/users'); }
  db.get('SELECT id, email, role FROM users WHERE id = ?', [id], (e, user) => {
    if (e || !user) { req.session.message = 'User not found.'; return res.redirect('/admin/users'); }
    if (user.role === 'admin') {
      db.get('SELECT COUNT(*) AS cnt FROM users WHERE role = ?', ['admin'], (err, row) => {
        const adminCount = row ? row.cnt : 0;
        if (adminCount <= 1) { req.session.message = 'Cannot ban the last admin.'; return res.redirect('/admin/users'); }
        db.run('UPDATE users SET banned = 1 WHERE id = ?', [id], (uErr) => {
          req.session.message = uErr ? 'Failed to ban user.' : `User ${user.email || ''} banned.`;
          return res.redirect('/admin/users');
        });
      });
    } else {
      db.run('UPDATE users SET banned = 1 WHERE id = ?', [id], (uErr) => {
        req.session.message = uErr ? 'Failed to ban user.' : `User ${user.email || ''} banned.`;
        return res.redirect('/admin/users');
      });
    }
  });
});

app.post('/admin/users/:id/unban', ensureAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) { req.session.message = 'Invalid user id.'; return res.redirect('/admin/users'); }
  db.run('UPDATE users SET banned = 0 WHERE id = ?', [id], (uErr) => {
    req.session.message = uErr ? 'Failed to unban user.' : 'User unbanned.';
    return res.redirect('/admin/users');
  });
});

app.post('/admin/users/:id/delete', ensureAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (Number.isNaN(id)) { req.session.message = 'Invalid user id.'; return res.redirect('/admin/users'); }
  if (req.user && req.user.id === id) { req.session.message = 'You cannot delete yourself.'; return res.redirect('/admin/users'); }
  db.get('SELECT id, email, role FROM users WHERE id = ?', [id], (e, user) => {
    if (e || !user) { req.session.message = 'User not found.'; return res.redirect('/admin/users'); }
    if (user.role === 'admin') {
      db.get('SELECT COUNT(*) AS cnt FROM users WHERE role = ?', ['admin'], (err, row) => {
        const adminCount = row ? row.cnt : 0;
        if (adminCount <= 1) { req.session.message = 'Cannot delete the last admin.'; return res.redirect('/admin/users'); }
        db.run('DELETE FROM users WHERE id = ?', [id], (dErr) => {
          req.session.message = dErr ? 'Failed to delete user.' : `User ${user.email || ''} deleted.`;
          return res.redirect('/admin/users');
        });
      });
    } else {
      db.run('DELETE FROM users WHERE id = ?', [id], (dErr) => {
        req.session.message = dErr ? 'Failed to delete user.' : `User ${user.email || ''} deleted.`;
        return res.redirect('/admin/users');
      });
    }
  });
});

initDb(() => {
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';
  const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
  db.get('SELECT * FROM users WHERE email = ?', [adminEmail], async (err, user) => {
    if (!user) {
      const hash = await bcrypt.hash(adminPass, 10);
      db.run(
        'INSERT INTO users (name, email, password_hash, role, email_verified, created_at) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)',
        ['Administrator', adminEmail, hash, 'admin', 1]
      );
      console.log(`Seeded admin user: ${adminEmail}`);
    } else if (!user.email_verified) {
      db.run('UPDATE users SET email_verified = 1 WHERE id = ?', [user.id]);
    }
    app.listen(PORT, () => console.log(`TicketSupport server running on http://localhost:${PORT}`));
  });
});

app.get('/verify/:token', (req, res) => {
  const { token } = req.params;
  if (!token) { req.session.message = 'Invalid verification link.'; return res.redirect('/login'); }
  db.get('SELECT * FROM users WHERE verify_token = ?', [token], (err, user) => {
    if (err || !user) { req.session.message = 'Invalid or expired verification link.'; return res.redirect('/login'); }
    if (user.email_verified) { req.session.message = 'Your email is already verified. Please log in.'; return res.redirect('/login'); }
    const now = new Date();
    const exp = user.verify_token_expires ? new Date(user.verify_token_expires) : null;
    if (!exp || exp < now) { req.session.message = 'Verification link has expired. Please request a new one.'; return res.redirect(`/verify/resend?email=${encodeURIComponent(user.email || '')}`); }
    db.run('UPDATE users SET email_verified = 1, verify_token = NULL, verify_token_expires = NULL WHERE id = ?', [user.id], (uErr) => {
      req.session.message = uErr ? 'Failed to verify email. Try again.' : 'Your email has been verified. You can now log in.';
      return res.redirect('/login');
    });
  });
});

app.get('/verify/resend', (req, res) => {
  const email = (req.query && req.query.email) ? String(req.query.email) : '';
  res.render('verify_resend', { email });
});

app.post('/verify/resend', (req, res) => {
  let { email } = req.body;
  email = (email || '').trim().toLowerCase();
  if (!email) { req.session.message = 'Please enter your email.'; return res.redirect('/verify/resend'); }
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) { req.session.message = 'Something went wrong.'; return res.redirect(`/verify/resend?email=${encodeURIComponent(email)}`); }
    if (!user) { req.session.message = 'If an account exists, a verification email has been sent.'; return res.redirect('/login'); }
    if (user.email_verified) { req.session.message = 'Your email is already verified. Please log in.'; return res.redirect('/login'); }
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    db.run('UPDATE users SET verify_token = ?, verify_token_expires = ? WHERE id = ?', [token, expires, user.id], async (uErr) => {
      if (uErr) { req.session.message = 'Could not generate verification link. Try again later.'; return res.redirect(`/verify/resend?email=${encodeURIComponent(email)}`); }
      try { await sendVerificationEmail(email, token, user.name || ''); } catch (e) { console.error('Failed to send verification email:', e.message); }
      req.session.message = 'Verification email sent. Please check your inbox.'; return res.redirect('/login');
    });
  });
});
