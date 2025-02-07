from flask import Flask, request, render_template, g
import sqlite3
import os
import logging

app = Flask(__name__)
DATABASE = 'users.db'

# Global flag to track SQL injection success
sql_injection_successful = False

# Create logs directory
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configure logging
logging.basicConfig(
    filename=os.path.join(log_dir, "system_logs.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Function to connect to the database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE)
    return db

# Function to close the database connection after each request
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    global sql_injection_successful
    message = ""

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        logging.info(f"Login attempt for username: {username}")

        # Check if SQL injection was successful
        if sql_injection_successful:
            message = "SQL Injection Successful! Any credentials now work!"
            logging.warning("Bypassing authentication due to successful SQL injection.")
            return render_template('login.html', message=message)

        try:
            # Choose between secure or vulnerable query
            use_secure_query = True  # Set this flag to True for secure query, False for vulnerable query

            if use_secure_query:
                query = "SELECT * FROM users WHERE username=? AND password=?"
                cursor = get_db().execute(query, (username, password))  # Secure query with parameters
            else:
                query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"  # Vulnerable query
                cursor = get_db().execute(query)  # Directly execute vulnerable query without parameters

            logging.info(f"Executing query: {query}")
            user = cursor.fetchone()
            cursor.close()

            if user:
                if not use_secure_query and "' OR '1'='1" in username:
                    sql_injection_successful = True
                    message = "SQL Injection Successful! Any credentials now work!"
                    logging.warning("SQL Injection attack detected and successful.")
                else:
                    message = "Login Successful!"
                    logging.info(f"Login successful for username: {username}")
            else:
                message = "Invalid Credentials!"
                logging.warning(f"Failed login attempt for username: {username}")
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            message = f"An error occurred during login: {e}"

    return render_template('login.html', message=message)

# Initialize the database and add dummy data
if __name__ == "__main__":
    conn = sqlite3.connect(DATABASE)
    conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    conn.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', '1234')")
    conn.commit()
    conn.close()

    logging.info("Database initialized and server started.")
    app.run(debug=True, host='127.0.0.1', port=5000)
