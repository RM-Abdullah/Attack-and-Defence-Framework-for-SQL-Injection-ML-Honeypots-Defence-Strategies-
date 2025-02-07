import random
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# --- Dataset Generation ---
# List of benign SQL queries (non-malicious)
benign_queries = [
    "SELECT * FROM users WHERE username='admin' AND password='password'",
    "SELECT id, name FROM employees WHERE department='HR'",
    "INSERT INTO orders (customer_id, product_id, quantity) VALUES (123, 456, 3)",
    "UPDATE users SET password='newpassword' WHERE username='john_doe'",
    "SELECT * FROM products WHERE category='electronics' AND price > 100"
]

# List of SQL injection queries (malicious)
sql_injection_queries = [
    "admin' OR '1'='1'",
    "' OR 1=1 --",
    "' UNION SELECT null, username, password FROM users --",
    "DROP TABLE users; --",
    "SELECT * FROM users WHERE username='admin' AND password='' OR 1=1 --",
    "'; EXEC xp_cmdshell('dir'); --",
    "admin' --"
]

# Generate a synthetic dataset with a balance of benign and malicious queries
num_samples = 1000  # Total number of samples to generate
data = []

for _ in range(num_samples // 2):
    # Add benign queries (label = 0)
    benign_query = random.choice(benign_queries)
    data.append([benign_query, 0])

    # Add malicious queries (label = 1)
    malicious_query = random.choice(sql_injection_queries)
    data.append([malicious_query, 1])

# Shuffle the dataset to mix benign and malicious queries
random.shuffle(data)

# Convert the list to a pandas DataFrame
df = pd.DataFrame(data, columns=["input_data", "label"])

# Save the dataset to a CSV file
df.to_csv("synthetic_sql_injection_dataset.csv", index=False)

print("Synthetic dataset created and saved as 'synthetic_sql_injection_dataset.csv'.")

# --- Training the Model ---
# Load the dataset
df = pd.read_csv("synthetic_sql_injection_dataset.csv")
X = df['input_data']  # Features (SQL queries)
y = df['label']  # Labels (0 = benign, 1 = malicious)

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Convert the text data into numerical features using TF-IDF
vectorizer = TfidfVectorizer()
X_train_vectorized = vectorizer.fit_transform(X_train)
X_test_vectorized = vectorizer.transform(X_test)

# Train a Random Forest Classifier
clf = RandomForestClassifier()
clf.fit(X_train_vectorized, y_train)

# Make predictions on the test set
y_pred = clf.predict(X_test_vectorized)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy on test set: {accuracy * 100:.2f}%")

# Save the trained model and vectorizer
joblib.dump(clf, 'ml_model.pkl')
joblib.dump(vectorizer, 'vectorizer.pkl')
print("Model and Vectorizer saved successfully!")
