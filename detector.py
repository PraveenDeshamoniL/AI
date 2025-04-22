
import joblib
import hashlib

model = joblib.load('phishing_model.pkl')

with open('malware_hashes.txt', 'r') as f:
    known_hashes = set(line.strip() for line in f)

def predict_url(url_text):
    return 'Phishing' if model.predict([url_text])[0] == 1 else 'Safe'

def check_malware(file_path):
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    return file_hash in known_hashes
