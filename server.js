const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pg = require('pg');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const path = require('path');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000;
const pool = new pg.Pool({ connectionString: process.env.DB_URL });

const recaptchaVerifyUrl = "https://www.google.com/recaptcha/api/siteverify";

app.post('/verify-recaptcha', async (req, res) => {
    try {
        const recaptchaResponse = await globalThis.fetch(recaptchaVerifyUrl, { method: 'POST' });

        const data = await recaptchaResponse.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: "Failed to verify reCAPTCHA" });
    }
});

app.listen(3000, () => console.log("Server running on port 3000"));

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Middleware to check authentication
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        req.user = null;
        return next();
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            req.user = null;
        } else {
            req.user = user;
        }
        next();
    });
};

app.get('/', (req, res) => {
    res.redirect('/login');  // Redirect to login page
});



app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// After successful registration, redirect with a success message
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password || password.length < 8) {
        return res.render('register', { error: 'Invalid input' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, email, password) VALUES ($1, $2, $3)', [username, email, hashedPassword]);
        res.redirect('/login?message=Account created successfully! Please log in.');
    } catch (err) {
        res.render('register', { error: 'Username or Email already exists' });
    }
});


// After successful login, redirect with a success message
app.post('/login', async (req, res) => {
    const { username, password, 'g-recaptcha-response': recaptcha } = req.body;

    if (!recaptcha) {
        return res.render('login', { error: 'reCAPTCHA verification failed' });
    }

    const recaptchaVerifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptcha}`;
    const recaptchaResponse = await globalThis.fetch(recaptchaVerifyUrl, { method: 'POST' });
    const recaptchaData = await recaptchaResponse.json();

    if (!recaptchaData.success) {
        return res.render('login', { error: 'Invalid reCAPTCHA' });
    }

    try {
        const user = await pool.query('SELECT * FROM users WHERE username=$1 OR email=$1', [username]);

        if (user.rows.length === 0) {
            return res.render('login', { error: 'User not found' });
        }

        const match = await bcrypt.compare(password, user.rows[0].password);
        if (!match) {
            return res.render('login', { error: 'Incorrect password' });
        }

        const token = jwt.sign({ id: user.rows[0].id, username: user.rows[0].username, email: user.rows[0].email }, process.env.JWT_SECRET, { expiresIn: '15m' });

        res.cookie('token', token, { httpOnly: true });
        res.redirect('/profile?message=Login successful!');
    } catch (err) {
        res.render('login', { error: 'Login error' });
    }
});

app.get('/profile', authenticateToken, async (req, res) => {
    if (!req.user) {
        return res.redirect('/login');
    }

    try {
        const user = await pool.query('SELECT id, username, email, created_at FROM users WHERE id=$1', [req.user.id]);
        res.render('profile', { user: user.rows[0] });
    } catch (err) {
        res.redirect('/login');
    }
});

// Logout with a success message
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login?message=Logout successful!');
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
