# University Lecturer Performance Review System

A secure web application for students to review lecturers, for lecturers to view their feedback, and for administrators to manage the system.

## Features

- **Students**: Register, log in, review lecturers on clarity, engagement, and punctuality
- **Lecturers**: Register, log in, view performance feedback and ratings
- **Admin**: Dashboard with statistics, manage lecturers, export reviews as CSV
- **Security**: CSRF protection, rate limiting, input sanitization, security headers, password hashing

## Tech Stack

- **Backend**: Python 3, Flask
- **Database**: SQLite (built into Python)
- **Frontend**: HTML5, CSS3 (responsive, mobile-first), vanilla JavaScript
- **Security**: Werkzeug password hashing, CSRF tokens, rate limiting

## Project Structure

```
LECTURER PERFOMANCE REVIEW SYSTEM 005/
├── app.py                 # Main Flask application
├── config.py              # Configuration (env-based)
├── requirements.txt       # Python dependencies
├── .env.example           # Example environment variables
├── .gitignore             # Git ignore rules
├── README.md              # This file
├── static/
│   ├── css/
│   │   └── styles.css     # Responsive stylesheet
│   ├── js/
│   │   └── main.js        # Frontend JavaScript
│   └── images/
│       └── favicon.svg    # Site favicon
└── templates/
    ├── base.html          # Base template with nav
    ├── index.html         # Home page (lecturer list)
    ├── thank_you.html     # Post-review confirmation
    ├── error.html         # Error pages (404, 429, 500)
    ├── auth/
    │   ├── student_login.html
    │   ├── student_register.html
    │   ├── lecturer_login.html
    │   ├── lecturer_register.html
    │   └── admin_login.html
    ├── student/
    │   ├── dashboard.html
    │   └── review.html
    ├── lecturer/
    │   └── dashboard.html
    └── admin/
        └── dashboard.html
```

## Setup & Installation

### 1. Clone the repository
```bash
git clone <repository-url>
cd "LECTURER PERFOMANCE REVIEW SYSTEM 005"
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
```bash
cp .env.example .env
# Edit .env with your settings (generate a strong SECRET_KEY)
```

Generate a secret key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Run the application
```bash
python app.py
```

### 6. Access the application
- **Students**: http://localhost:5000
- **Admin**: http://localhost:5000/admin/login
- **Phone (same WiFi)**: http://<your-pc-ip>:5000

## Security Features

- **CSRF Protection**: All POST forms include CSRF tokens
- **Rate Limiting**: In-memory rate limiter prevents abuse
- **Input Sanitization**: All user input is sanitized and validated
- **Password Hashing**: Werkzeug's `generate_password_hash` (PBKDF2)
- **Security Headers**: X-Frame-Options, CSP, X-XSS-Protection, etc.
- **Session Security**: HttpOnly, SameSite, Secure cookies

## Default Admin Credentials

Change these in `.env` before deploying:
- Username: `admin`
- Password: `change-me-immediately`

## License

&copy; 2026 Masterui University. All rights reserved.
