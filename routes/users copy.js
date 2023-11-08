const express = require('express');
const router = express.Router();
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const MySQLStore2 = require('express-mysql-session')(session);

// Database
const dbConfig = {
  host: '185.27.133.13',
  user: 'viewster_root',
  password: '123viewster.',
  database: 'viewster_backend'
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'tua-email@gmail.com', 
    pass: 'tua-password'
  }
});

const MySQLStore = require('express-mysql-session')(session);

const sessionStore = new MySQLStore2({}, dbConfig);

router.use(session({
  secret: 'viewster_aaron_manu',
  resave: false,
  saveUninitialized: true,
  store: sessionStore
}));

router.use(passport.initialize());
router.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id); // Salva l'ID dell'utente nella sessione
});

passport.deserializeUser((id, done) => {
  const checkQuery = 'SELECT * FROM users WHERE id = ?'; // Supponendo che l'ID dell'utente sia memorizzato nel campo 'id'

  pool.query(checkQuery, [id], (checkError, checkResults) => {
    if (checkError) {
      console.error(checkError);
      return done(checkError, null);
    }
    console.log<("Ciao");
    if (checkResults.length > 0) {
      const user = checkResults[0];
      return done(null, user); // Questo utente verrà memorizzato in req.user
    } else {
      return done(null, null); // Utente non trovato
    }
  });
});

passport.use(new GoogleStrategy({
  clientID: '373721254470-47gt9m3jiclkll427q2tujm9q6h2d3a8.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: '/users/auth/google/callback'
},

async (accessToken, refreshToken, profile, done) => {
  try {
    // Verifica se l'utente esiste nel database
    const checkQuery = 'SELECT * FROM users WHERE email = ?';

    pool.query(checkQuery, profile.emails[0].value, (checkError, checkResults) => {
      if (checkError) {
        console.error(checkError);
        // Gestisci l'errore inviando una risposta di errore
        return done(checkError, null);
      }

      if (checkResults.length > 0) {
        // Utente esiste nel database, restituisci l'utente autenticato
        return done(null, { ...profile, accessToken, refreshToken });
      } else {
        // Utente non esiste, crea un nuovo utente nel database
        const insertQuery = 'INSERT INTO users (googleId, email, accessToken, refreshToken, phone) VALUES (?, ?, ?, ?, ?)';
        const insertValues = [profile.id, profile.emails[0].value, accessToken, refreshToken, profile.phoneNumbers && profile.phoneNumbers.length > 0 ? profile.phoneNumbers[0].value : null];

        pool.query(insertQuery, insertValues, (insertError, insertResults) => {
          if (insertError) {
            console.error(insertError);
            // Gestisci l'errore inviando una risposta di errore
            return done(insertError, null);
          }
          
          const userId = insertResults.insertId;
          // Restituisci l'utente appena creato
          return done(null, { ...profile, accessToken, refreshToken, userId });
        });
      }
    });
  } catch (error) {
    console.error(error);
    // Gestisci l'errore inviando una risposta di errore
    return done(error, null);
  }
}));

router.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // Redirect dopo l'autenticazione riuscita
    res.redirect('http://localhost:3000/dashboard');
  }
);

const pool = mysql.createPool(dbConfig);

pool.query('SELECT 1 + 1', (err, rows) => {
  if (err) {
    console.error('Query error:', err);
    return;
  }
  console.log('Query executed successfully:', rows);
});

// Login
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  const query = 'SELECT * FROM users WHERE email = ?';
  pool.query(query, [email], async (err, results) => {
    if (err) {
      console.error('Query error:', err);
      return res.status(500).json({ error: 'Server error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = results[0];
    const hashedPassword = user.password;

    try {
      const match = await bcrypt.compare(password, hashedPassword);
      if (match) {
        return res.status(200).json(user);
      } else {
        return res.status(401).json({ error: 'Invalid email or password' });
      }
    } catch (error) {
      console.error('Error comparing passwords:', error);
      return res.status(500).json({ error: 'Server error' });
    }
  });
});

// Get user
router.get('/user', (req, res) => {
    const { uid } = req.query;
    const query = 'SELECT * FROM users WHERE id = ?';
    pool.query(query, [uid], (err, results) => {
      if (err) {
        console.error('Query error:', err);
        res.status(500).json({ error: 'Server error' });
        return;
      }
      return res.status(200).json(results);
    });
});

const saltRounds = 10;
router.post('/createUser', async (req, res) => {
    const { email, password, firstname, lastname, phone, countryPhone } = req.body;
  
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }
  
    try {
      const checkQuery = 'SELECT * FROM users WHERE email = ?';
      pool.query(checkQuery, [email], (checkError, checkResults) => {
        if (checkError) {
          console.error(checkError);
          return res.status(500).json({ error: 'An error occurred. Please try again later.' });
        }
  
        if (checkResults.length > 0) {
          return res.status(409).json({ error: 'Email already exists' });
        }

        bcrypt.hash(password, saltRounds, (hashError, hashedPassword) => {
          if (hashError) {
            console.error(hashError);
            return res.status(500).json({ error: 'An error occurred. Please try again later.' });
          }
  
          const insertQuery = 'INSERT INTO users (email, password, firstname, lastname, phone, countryphone) VALUES (?, ?, ?, ?, ?, ?)';
          
          pool.query(insertQuery, [ email, hashedPassword, firstname, lastname, phone, countryPhone ], (insertError, insertResults) => {
            if (insertError) {
              console.error(insertError);
              return res.status(500).json({ error: 'An error occurred. Please try again later.' });
            }
  
            const userId = insertResults.insertId;
            return res.status(200).json({ uid: userId });
          });
        });
      });
    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: 'An error occurred. Please try again later.' });
    }
});

router.post('/request-reset-password', (req, res) => {
  const { email } = req.body;

  // Esegui una query per verificare se l'email esiste nel database
  pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      console.error('Query error:', err);
      res.status(500).json({ error: 'Server error' });
      return;
    }

    if (results.length > 0) {
      const resetToken = crypto.randomBytes(20).toString('hex');
      
      pool.query('UPDATE users SET resetToken = ?, resetTokenExpires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE email = ?', [resetToken, email], (updateErr, updateResults) => {
        if (updateErr) {
          console.error('Update error:', updateErr);
          res.status(500).json({ error: 'Server error' });
        } else {
          
          const mailOptions = {
            from: 'tua-email@gmail.com', // Il mittente dell'email
            to: email, // Il destinatario dell'email
            subject: 'Reset Password', // Oggetto dell'email
            text: `Clicca su questo link per reimpostare la tua password: http://tuosito.com/reset-password?token=${resetToken}` // Testo dell'email con il link di reset password
          };

          transporter.sendMail(mailOptions, (mailErr, info) => {
            if (mailErr) {
              console.error('Email error:', mailErr);
              res.status(500).json({ error: 'Errore durante l\'invio dell\'email' });
            } else {
              res.json({ message: 'Email inviata con successo. Controlla la tua casella di posta.' });
            }
          });
        }
      });
    } else {
      res.status(404).json({ message: 'Utente non trovato' });
    }
  });
});

router.post('/reset-password', (req, res) => {
  const { email, resetToken, newPassword } = req.body;
  
  pool.query('SELECT * FROM users WHERE email = ? AND resetToken = ? AND resetTokenExpires > NOW()', [email, resetToken], (err, results) => {
    if (err) {
      console.error('Query error:', err);
      res.status(500).json({ error: 'Server error' });
      return;
    }

    if (results.length > 0) {
      pool.query('UPDATE users SET password = ? WHERE email = ?', [newPassword, email], (err, updateResults) => {
        if (err) {
          console.error('Update error:', err);
          res.status(500).json({ error: 'Server error' });
        } else {
          res.json({ message: 'Password reimpostata con successo' });
        }
      });
    } else {
      res.status(400).json({ message: 'Token non valido o scaduto' });
    }
  });
});

router.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    
    res.redirect('/dashboard');
  }
);

module.exports = router;