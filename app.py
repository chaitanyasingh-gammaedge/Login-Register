from flask import Flask
from config import Config
from models import db
from routes import auth_bp, bcrypt, mail
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)
mail.init_app(app)
jwt = JWTManager(app)

app.register_blueprint(auth_bp, url_prefix="/api")

@app.route("/")
def home():
    return {"msg": "Flask Auth API is running!"}

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)




# app.py
# import os
# import datetime
# from functools import wraps
# from flask import Flask, request, jsonify, send_from_directory
# from flask_cors import CORS
# from werkzeug.utils import secure_filename
# from werkzeug.security import generate_password_hash, check_password_hash
# import jwt
# import mysql.connector
# from validate_email_address import validate_email

# # Load config from env (you can move to config.py)
# DB_HOST = os.getenv("DB_HOST", "localhost")
# DB_USER = os.getenv("DB_USER", "root")
# DB_PASS = os.getenv("DB_PASS", "")
# DB_NAME = os.getenv("DB_NAME", "")
# SECRET_KEY = os.getenv("SECRET_KEY", "pvhSecretKey@123")
# ACCESS_TOKEN_EXPIRES_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRES_MIN", "60")) 
# REFRESH_TOKEN_EXPIRES_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRES_DAYS", "7"))
# UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "uploads")
# ALLOWED_EXTENSIONS = {"mp4", "mov", "avi", "mkv", "png", "jpg", "jpeg"}

# # Ensure upload folder exists
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# app = Flask(__name__)
# app.config['SECRET_KEY'] = SECRET_KEY
# app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

# def get_db_connection():
#     """Return a fresh MySQL connection. Caller must close it."""
#     return mysql.connector.connect(
#         host=DB_HOST,
#         user=DB_USER,
#         password=DB_PASS,
#         database=DB_NAME,
#         autocommit=False
#     )

# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# def create_access_token(payload: dict):
#     exp = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRES_MIN)
#     payload_copy = payload.copy()
#     payload_copy.update({"exp": exp, "type": "access"})
#     token = jwt.encode(payload_copy, app.config['SECRET_KEY'], algorithm="HS256")
#     return token

# def create_refresh_token(payload: dict):
#     exp = datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS)
#     payload_copy = payload.copy()
#     payload_copy.update({"exp": exp, "type": "refresh"})
#     token = jwt.encode(payload_copy, app.config['SECRET_KEY'], algorithm="HS256")
#     return token

# def token_required(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         auth_header = request.headers.get("Authorization", None)
#         if not auth_header:
#             return jsonify({"error": "Authorization header missing"}), 401
#         parts = auth_header.split()
#         if parts[0].lower() != "bearer" or len(parts) != 2:
#             return jsonify({"error": "Invalid Authorization header format. Use: Bearer <token>"}), 401
#         token = parts[1]
#         try:
#             payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#             if payload.get("type") != "access":
#                 return jsonify({"error": "Invalid token type"}), 401
#             email = payload.get("email")
#             if not email:
#                 return jsonify({"error": "Invalid token payload"}), 401

#             conn = get_db_connection()
#             cursor = conn.cursor(dictionary=True)
#             cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
#             user = cursor.fetchone()
#             cursor.close()
#             conn.close()

#             if not user:
#                 return jsonify({"error": "User not found"}), 404

#             # pass user to route as keyword arg
#             kwargs['current_user'] = user
#             return func(*args, **kwargs)

#         except jwt.ExpiredSignatureError:
#             return jsonify({"error": "Token expired"}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({"error": "Invalid token"}), 401
#         except Exception as e:
#             return jsonify({"error": f"Server error: {str(e)}"}), 500

#     return wrapper

# @app.route("/signup", methods=["POST"])
# def signup():
#     data = request.json or {}
#     first_name = data.get("firstNm")
#     last_name = data.get("LastNm")
#     linkedin = data.get("linkedin")
#     email = data.get("email")
#     password = data.get("password")
#     confirm_password = data.get("confirm_password")

#     if not all([first_name, last_name, email, password, confirm_password]):
#         return jsonify({"error": "Missing required fields"}), 400
#     if not validate_email(email):
#         return jsonify({"error": "Invalid email address"}), 400
#     if password != confirm_password:
#         return jsonify({"error": "Passwords do not match"}), 400

#     hashed_password = generate_password_hash(password)

#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT id FROM Users WHERE email = %s", (email,))
#         if cursor.fetchone():
#             cursor.close()
#             conn.close()
#             return jsonify({"error": "User with this email already exists"}), 409

#         cursor.execute(
#             """
#             INSERT INTO Users (first_name, last_name, linkedin_profile, email, password_hash, created_at)
#             VALUES (%s, %s, %s, %s, %s, NOW())
#             """,
#             (first_name, last_name, linkedin, email, hashed_password)
#         )
#         conn.commit()
#         cursor.close()
#         conn.close()
#         return jsonify({"message": "User registered successfully"}), 201

#     except mysql.connector.Error as e:
#         return jsonify({"error": "Database error", "details": str(e)}), 500
#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# @app.route("/login", methods=["POST"])
# def login():
#     data = request.json or {}
#     email = data.get("email")
#     password = data.get("password")
#     if not all([email, password]):
#         return jsonify({"error": "Missing email or password"}), 400

#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT id, first_name, email, password_hash FROM Users WHERE email = %s", (email,))
#         row = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if not row:
#             return jsonify({"error": "Invalid credentials"}), 403

#         user_id, first_name, user_email, pw_hash = row
#         if not check_password_hash(pw_hash, password):
#             return jsonify({"error": "Invalid credentials"}), 403

#         access_token = create_access_token({"email": user_email, "id": user_id})
#         refresh_token = create_refresh_token({"email": user_email, "id": user_id})

#         # Store refresh token in DB (optional but recommended)
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("INSERT INTO RefreshTokens (user_id, token, expires_at) VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL %s DAY))",
#                        (user_id, refresh_token, REFRESH_TOKEN_EXPIRES_DAYS))
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return jsonify({
#             "message": "Login successful",
#             "access_token": access_token,
#             "refresh_token": refresh_token,
#             "user": {"id": user_id, "firstNm": first_name, "email": user_email}
#         }), 200

#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# @app.route("/token/refresh", methods=["POST"])
# def refresh_token():
#     data = request.json or {}
#     refresh = data.get("refresh_token")
#     if not refresh:
#         return jsonify({"error": "Missing refresh token"}), 400
#     try:
#         payload = jwt.decode(refresh, app.config['SECRET_KEY'], algorithms=["HS256"])
#         if payload.get("type") != "refresh":
#             return jsonify({"error": "Invalid refresh token"}), 401
#         user_id = payload.get("id")
#         email = payload.get("email")

#         # verify token is present in DB
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT id FROM RefreshTokens WHERE user_id = %s AND token = %s AND revoked = 0 AND expires_at > NOW()", (user_id, refresh))
#         row = cursor.fetchone()
#         cursor.close()
#         conn.close()
#         if not row:
#             return jsonify({"error": "Refresh token invalid or revoked"}), 401

#         new_access = create_access_token({"email": email, "id": user_id})
#         return jsonify({"access_token": new_access}), 200

#     except jwt.ExpiredSignatureError:
#         return jsonify({"error": "Refresh token expired"}), 401
#     except jwt.InvalidTokenError:
#         return jsonify({"error": "Invalid refresh token"}), 401
#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# @app.route("/logout", methods=["POST"])
# @token_required
# def logout(current_user):
#     # Revoke refresh tokens for user
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("UPDATE RefreshTokens SET revoked = 1 WHERE user_id = %s", (current_user['id'],))
#         conn.commit()
#         cursor.close()
#         conn.close()
#         return jsonify({"message": "Logged out (refresh tokens revoked)"}), 200
#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# @app.route("/apply", methods=["POST"])
# @token_required
# def apply(current_user):
#     try:
#         # form fields
#         email = request.form.get('email') or current_user.get('email')
#         linkedIn = request.form.get('linkedIn')
#         phone_number = request.form.get('phoneNumber')
#         education_background = request.form.get('educationBackground')
#         experience = request.form.get('experience')

#         # files
#         founder_video = request.files.get('founderVideo')
#         demo_video = request.files.get('demoVideo')

#         if not email or not validate_email(email):
#             return jsonify({"error": "Invalid or missing email"}), 400

#         # save files safely using secure_filename
#         founder_video_path = None
#         demo_video_path = None
#         if founder_video and founder_video.filename and allowed_file(founder_video.filename):
#             fname = secure_filename(f"{current_user['id']}_founder_{founder_video.filename}")
#             founder_video_path = os.path.join(app.config['UPLOAD_FOLDER'], fname)
#             founder_video.save(founder_video_path)
#         if demo_video and demo_video.filename and allowed_file(demo_video.filename):
#             dname = secure_filename(f"{current_user['id']}_demo_{demo_video.filename}")
#             demo_video_path = os.path.join(app.config['UPLOAD_FOLDER'], dname)
#             demo_video.save(demo_video_path)

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute(
#             """
#             INSERT INTO Applications
#             (user_id, email, linkedIn, phone_number, education_background, experience, founder_video, demo_video, created_at)
#             VALUES (%s,%s,%s,%s,%s,%s,%s,%s,NOW())
#             """,
#             (current_user['id'], email, linkedIn, phone_number, education_background, experience, founder_video_path, demo_video_path)
#         )
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return jsonify({"message": "Application submitted successfully"}), 201

#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# @app.route("/profile", methods=["GET"])
# @token_required
# def profile(current_user):
#     try:
#         user_data = {
#             "id": current_user['id'],
#             "first_name": current_user['first_name'],
#             "last_name": current_user['last_name'],
#             "email": current_user['email'],
#             "linkedin_profile": current_user.get('linkedin_profile'),
#             "profile_icon_url": None
#         }
#         if current_user.get('profile_icon'):
#             user_data['profile_icon_url'] = f"/uploads/{current_user.get('profile_icon')}"
#         return jsonify(user_data), 200
#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# @app.route("/profile/update", methods=["POST"])
# @token_required
# def update_profile(current_user):
#     try:
#         first = request.form.get("firstNm")
#         last = request.form.get("LastNm")
#         linkedin = request.form.get("linkedin")
#         profile_file = request.files.get("profileIcon")

#         profile_filename = None
#         if profile_file and profile_file.filename and allowed_file(profile_file.filename):
#             profile_filename = secure_filename(f"{current_user['id']}_icon_{profile_file.filename}")
#             profile_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_filename)
#             profile_file.save(profile_path)

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         updates = []
#         params = []
#         if first:
#             updates.append("first_name=%s"); params.append(first)
#         if last:
#             updates.append("last_name=%s"); params.append(last)
#         if linkedin:
#             updates.append("linkedin_profile=%s"); params.append(linkedin)
#         if profile_filename:
#             updates.append("profile_icon=%s"); params.append(profile_filename)

#         if updates:
#             sql = "UPDATE Users SET " + ", ".join(updates) + " WHERE id = %s"
#             params.append(current_user['id'])
#             cursor.execute(sql, tuple(params))
#             conn.commit()

#         cursor.close()
#         conn.close()
#         return jsonify({"message": "Profile updated"}), 200

#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# @app.route('/uploads/<path:filename>', methods=['GET'])
# def uploaded_file(filename):
#     """Serve uploaded files (in dev only). In production, use cdn or object storage + proper auth."""
#     return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# # Password reset -- step 1: request token (we store a single-use token in DB)
# @app.route("/password-reset/request", methods=["POST"])
# def password_reset_request():
#     data = request.json or {}
#     email = data.get("email")
#     if not email or not validate_email(email):
#         return jsonify({"error": "Invalid email"}), 400
#     try:
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute("SELECT id FROM Users WHERE email = %s", (email,))
#         row = cursor.fetchone()
#         if not row:
#             cursor.close()
#             conn.close()
#             # avoid disclosing that user doesn't exist
#             return jsonify({"message": "If that email exists, you'll receive password reset instructions"}), 200

#         user_id = row[0]
#         # create a one-time token (refresh-like with short expiry)
#         token = jwt.encode({"email": email, "id": user_id, "type": "pwreset", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
#         # store token
#         cursor.execute("INSERT INTO PasswordResets (user_id, token, expires_at, used) VALUES (%s,%s, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)", (user_id, token))
#         conn.commit()
#         cursor.close()
#         conn.close()
#         # TODO: send email with token link (e.g., /password-reset/confirm?token=...)
#         return jsonify({"message": "If that email exists, you'll receive password reset instructions", "reset_token_preview": token}), 200

#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# # Password reset -- step 2: confirm using token and set new password
# @app.route("/password-reset/confirm", methods=["POST"])
# def password_reset_confirm():
#     data = request.json or {}
#     token = data.get("token")
#     new_password = data.get("new_password")
#     confirm = data.get("confirm_password")
#     if not all([token, new_password, confirm]):
#         return jsonify({"error": "Missing fields"}), 400
#     if new_password != confirm:
#         return jsonify({"error": "Passwords do not match"}), 400
#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
#         if payload.get("type") != "pwreset":
#             return jsonify({"error": "Invalid token"}), 400
#         user_id = payload.get("id")

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         # verify token exists and not used and not expired
#         cursor.execute("SELECT id, used FROM PasswordResets WHERE token = %s AND user_id = %s AND expires_at > NOW()", (token, user_id))
#         row = cursor.fetchone()
#         if not row:
#             cursor.close()
#             conn.close()
#             return jsonify({"error": "Invalid or used token"}), 400
#         if row[1] == 1:
#             cursor.close()
#             conn.close()
#             return jsonify({"error": "Token already used"}), 400

#         hashed = generate_password_hash(new_password)
#         cursor.execute("UPDATE Users SET password_hash = %s WHERE id = %s", (hashed, user_id))
#         cursor.execute("UPDATE PasswordResets SET used = 1 WHERE id = %s", (row[0],))
#         conn.commit()
#         cursor.close()
#         conn.close()
#         return jsonify({"message": "Password reset successful"}), 200

#     except jwt.ExpiredSignatureError:
#         return jsonify({"error": "Reset token expired"}), 400
#     except jwt.InvalidTokenError:
#         return jsonify({"error": "Invalid token"}), 400
#     except Exception as e:
#         return jsonify({"error": "Server error", "details": str(e)}), 500

# if __name__ == "__main__":
#     # For dev: host=0.0.0.0 if you want other machines to connect
#     app.run(debug=True, port=5000)
