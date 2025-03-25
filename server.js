const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pg = require('pg');
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');


dotenv.config();
const app = express();
const PORT = process.env.PORT || 4000;
const pool = new pg.Pool({ connectionString: process.env.DB_URL });

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

const recaptchaVerifyUrl = "https://www.google.com/recaptcha/api/siteverify";

// ✅ Function to check if the users table exists and create it if not
const initializeDatabase = async () => {
    try {
        const result = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'users'
            );
        `);

        if (!result.rows[0].exists) {
            console.log("Creating 'users' table...");
            const sqlFilePath = path.join(__dirname, 'database.sql');

            if (fs.existsSync(sqlFilePath)) {
                console.log("Running SQL file: database.sql");
                const sqlQuery = fs.readFileSync(sqlFilePath, 'utf-8');
                await pool.query(sqlQuery);
                console.log("Database initialized successfully.");
            } else {
                console.log("No database.sql file found. Creating table manually...");
                await pool.query(`
                    CREATE TABLE users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                `);
                console.log("'users' table created successfully.");
            }
        } else {
            console.log("'users' table already exists.");
        }
    } catch (error) {
        console.error("Error initializing database:", error);
    }
};

// ✅ Run the function when the server starts
initializeDatabase();



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
    const { username, password } = req.body;
    const recaptcha = req.body['g-recaptcha-response'];  // Correct field name

    if (!recaptcha) {
        return res.render('login', { error: 'reCAPTCHA verification failed' });
    }

    try {
        // Validate reCAPTCHA
        const recaptchaVerifyUrl = "https://www.google.com/recaptcha/api/siteverify";
        const recaptchaSecret = process.env.RECAPTCHA_SECRET_KEY;
        const recaptchaResponse = await fetch(recaptchaVerifyUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ secret: recaptchaSecret, response: recaptcha })
        });

        const recaptchaData = await recaptchaResponse.json();

        if (!recaptchaData.success) {
            console.log("reCAPTCHA failed:", recaptchaData);
            return res.render('login', { error: 'Invalid reCAPTCHA. Please try again.' });
        }

        // Check user credentials
        const userResult = await pool.query('SELECT * FROM users WHERE username=$1 OR email=$1', [username]);

        if (userResult.rows.length === 0) {
            return res.render('login', { error: 'User not found' });
        }

        const user = userResult.rows[0];
        const match = await bcrypt.compare(password, user.password);
        
        if (!match) {
            return res.render('login', { error: 'Incorrect password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.cookie('token', token, { httpOnly: true });
        res.redirect('/profile?message=Login successful!');
    } catch (err) {
        console.error("Login error:", err);
        res.render('login', { error: 'Login error. Please try again later.' });
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
