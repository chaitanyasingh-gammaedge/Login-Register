A secure authentication backend built with **Flask**, **JWT**, **MySQL**, and **Flask-Mail**, providing user registration, login with tokens, and email notifications on login.

---

## 🚀 Features
- 🔑 User Registration & Login
- 🧠 Password Hashing (Bcrypt)
- 💬 JWT Access & Refresh Tokens
- ✉️ Email Notification on Successful Login
- 💾 MySQL Database Integration
- 🌍 Environment Variable Support (`.env`)

---

## 🧩 Project Structure
accesstoken/
│
├── app.py
├── config.py
├── models.py
├── routes.py
├── utils.py
├── .env
└── README.md



---

## ⚙️ Requirements
- Python 3.10+
- MySQL 8.0+
- Virtual Environment (recommended: `.venv`)

---

## 📦 Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone <your-repo-url>
cd accesstoken

python3 -m venv .venv
source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate      # Windows

INstall dependencies:
pip install -r requirements.txt

🔑 Environment Configuration

Create a .env file in your project root and add:
SECRET_KEY=
SQLALCHEMY_DATABASE_URI=
JWT_SECRET_KEY=

MAIL_SERVER=
MAIL_PORT=
MAIL_USE_TLS=
MAIL_USERNAME=
MAIL_PASSWORD=


Database setup:
CREATE DATABASE flask_auth_db;


Run the application:
flask run

