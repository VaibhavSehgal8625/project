# Authentication System

A simple authentication system built with Node.js, Express, PostgreSQL, and EJS. It supports user registration, login, logout, and session management using JWT authentication.

## Features
- User registration with hashed passwords
- Login with username or email
- JWT authentication stored in cookies
- Logout functionality
- Google reCAPTCHA verification for login
- PostgreSQL database for user storage
- EJS templating engine with Tailwind CSS for UI

---

## Installation

### Prerequisites
Ensure you have the following installed:
- [Node.js](https://nodejs.org/) (Latest LTS version recommended)
- [PostgreSQL](https://www.postgresql.org/)
- [Git](https://git-scm.com/)

### Step-by-Step Setup

#### 1. Clone the Repository
```sh
git clone https://github.com/yourusername/authentication-system.git
cd authentication-system
```

#### 2. Install Dependencies
```sh
npm install
```

#### 3. Set Up PostgreSQL Database
Create a PostgreSQL database and a `users` table using the following query:
```sql
CREATE TABLE users (
    email VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 4. Configure Environment Variables
Create a `.env` file in the project root and add the following:
```env
PORT=4000
DB_URL=postgres://your_db_user:your_db_password@localhost:5432/your_database
JWT_SECRET=your_jwt_secret_key
RECAPTCHA_SITE_KEY=your_google_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_google_recaptcha_secret_key
```
> Replace `your_db_user`, `your_db_password`, `your_database`, and other values with your actual credentials.

#### 5. Start the Server
```sh
npm start
```
The server will run at `http://localhost:4000`

---

## Usage
### Default Routes
- `/` → Redirects to the login page
- `/register` → User registration page
- `/login` → User login page
- `/profile` → User profile (requires authentication)
- `/logout` → Logs out the user

### API Endpoints
| Method | Endpoint           | Description                |
|--------|-------------------|----------------------------|
| GET    | `/`               | Redirects to login         |
| GET    | `/register`       | Renders registration page  |
| POST   | `/register`       | Handles user registration  |
| GET    | `/login`          | Renders login page         |
| POST   | `/login`          | Handles user login         |
| GET    | `/profile`        | Displays user profile      |
| GET    | `/logout`         | Logs out user & clears JWT |

---

## Technologies Used
- **Backend**: Node.js, Express.js
- **Database**: PostgreSQL
- **Authentication**: JWT, bcrypt
- **Frontend**: EJS, Tailwind CSS
- **Security**: Google reCAPTCHA, Cookies

---

## Troubleshooting
- If `fetch is not a function`, add `globalThis.fetch = require('node-fetch');` at the top of `server.js`.
- If PostgreSQL connection fails, check your `DB_URL` in `.env`.
- If you get JWT errors, try deleting browser cookies and relogging.

---

## License
This project is open-source and available under the [MIT License](LICENSE).

---

## Author
Developed by **Your Name**. Feel free to contribute and improve!

