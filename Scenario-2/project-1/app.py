from flask import Flask, request, render_template, g
import sqlite3
import os
import logging
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import joblib

app = Flask(__name__)
DATABASE = 'users.db'

# Load ML model and vectorizer
ML_MODEL_PATH = 'ml_model.pkl'
VECTORIZER_PATH = 'vectorizer.pkl'

ml_model = joblib.load(ML_MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"  # System email
SENDER_PASSWORD = "your_password"  # System email password
RECEIVER_EMAIL = "recipient_email@gmail.com"  # Recipient email

# Log directory setup
log_dir = os.path.join(os.getcwd(), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Honeypot log directory
honeypot_log_dir = os.path.join(os.getcwd(), "honeypot")
if not os.path.exists(honeypot_log_dir):
    os.makedirs(honeypot_log_dir)

# Configure system logging
logging.basicConfig(
    filename=os.path.join(log_dir, "system_logs.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Configure honeypot logging
honeypot_logger = logging.getLogger("honeypot")
honeypot_handler = logging.FileHandler(os.path.join(honeypot_log_dir, "honeypot_logs.log"))
honeypot_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
honeypot_logger.addHandler(honeypot_handler)
honeypot_logger.setLevel(logging.INFO)

# Database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Function to send email alerts
def send_email_alert(subject, message):
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()

        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

# ML model prediction
def predict_with_ml(input_data):
    vectorized_data = vectorizer.transform([input_data])
    prediction = ml_model.predict(vectorized_data)
    return prediction[0]  # 0 = benign, 1 = malicious

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    message = ""
    sql_injection_detected = False  # Flag for SQL injection detection
    ml_detected = False             # Flag for ML detection
    use_secure_query = True        # Set to True for secure, parameterized queries

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        combined_input = f"{username} {password}"

        logging.info(f"Login attempt: username='{username}' at {datetime.now()}")

        # 1. SQL Injection Detection
        if ("'" in username or "--" in username or ";" in username):
            sql_injection_detected = True
            logging.warning(f"Potential SQL injection detected! Username: {username}")

            if not use_secure_query:
                # Vulnerable query scenario
                honeypot_logger.warning(f"Honeypot triggered! Username: {username}, Password: {password}")
                send_email_alert(
                    "Honeypot Triggered (SQL Injection)",
                    f"Honeypot activity detected:\nUsername: {username}\nPassword: {password}\nTime: {datetime.now()}"
                )
                message = "SQL Injection Successful!"
            else:
                # Secure query blocks injection
                message = "SQL Injection Failed!"
                logging.info("SQL Injection attempt blocked due to secure query usage.")

        # 2. Bypass ML for valid credentials
        if username == "admin" and password == "1234":
            message = "Login Successful!"
            logging.info(f"Login successful for username: {username}")

        # 3. Invalid credentials for "admin" with wrong password
        elif username == "admin" and password != "1234":
            message = "Invalid Credentials!"
            logging.warning(f"Invalid credentials for username: {username}")

        # 4. ML-Based Detection for unknown inputs
        elif not sql_injection_detected:
            prediction = predict_with_ml(combined_input)
            if prediction == 1:  # Malicious input detected by ML
                ml_detected = True
                logging.warning(f"Suspicious activity detected by ML! Username: {username}")
                send_email_alert(
                    "Suspicious Activity Detected (ML)",
                    f"ML flagged suspicious input:\nUsername: {username}\nTime: {datetime.now()}"
                )
                message = "Suspicious activity detected!"

        # 5. Database Query (Parameterized if `use_secure_query` is True)
        if not message and not sql_injection_detected and not ml_detected:
            if use_secure_query:
                query = "SELECT * FROM users WHERE username=? AND password=?"
                cursor = get_db().execute(query, (username, password))
            else:
                query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                cursor = get_db().execute(query)

            user = cursor.fetchone()
            cursor.close()

            if user:
                message = "Login Successful!"
                logging.info(f"Login successful for username: {username}")
            else:
                message = "Invalid Credentials!"
                logging.warning(f"Failed login attempt for username: {username}")

    return render_template('login.html', message=message)



# Honeypot route
@app.route('/fake-login', methods=['POST'])
def honeypot():
    username = request.form['username']
    password = request.form['password']
    honeypot_logger.warning(f"Honeypot triggered! Username: {username}, Password: {password}")
    send_email_alert(
        "Honeypot Triggered",
        f"Honeypot activity detected:\nUsername: {username}\nPassword: {password}\nTime: {datetime.now()}"
    )
    return "Suspicious activity detected!", 403

# Initialize the database and add dummy data
if __name__ == "__main__":
    conn = sqlite3.connect(DATABASE)
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', '1234')")
    conn.commit()
    conn.close()

    logging.info("Database initialized and server started.")
    app.run(debug=True, host='127.0.0.1', port=5000)
