import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from User.views import (
    get_url_length, count_letters, count_digits,
    count_special_chars, has_shortening_service,
    abnormal_url, secure_http, have_ip_address,
    extract_root_domain, hash_encode, get_url_region,
    train_model
)

# Test feature extraction
test_urls = [
    "https://google.com",
    "http://bit.ly/malicious",
    "https://suspicious-site.ru/login",
    "https://github.com/user/repo"
]

print("Testing feature extraction:")
for url in test_urls:
    url_len = get_url_length(url)
    letters = count_letters(url)
    digits = count_digits(url)
    special = count_special_chars(url)
    shortened = has_shortening_service(url)
    abnormal = abnormal_url(url)
    secure = secure_http(url)
    have_ip = have_ip_address(url)
    pri_domain = extract_root_domain(url)
    region = hash_encode(get_url_region(pri_domain))
    root_dom = hash_encode(pri_domain)
    
    print(f"\nURL: {url}")
    print(f"  Features: len={url_len}, letters={letters}, digits={digits}, special={special}")
    print(f"  shortened={shortened}, abnormal={abnormal}, secure={secure}, ip={have_ip}")
    print(f"  domain={pri_domain}, region={region}, root_dom={root_dom}")

# Test training
print("\n\nTesting model training...")
success = train_model()
print(f"Training success: {success}")

# Test prediction if model trained
from User.views import pipeline, model_trained
if model_trained and pipeline:
    print("\n\nTesting prediction:")
    import numpy as np
    url = "https://google.com"
    url_len = get_url_length(url)
    letters = count_letters(url)
    digits = count_digits(url)
    special = count_special_chars(url)
    shortened = has_shortening_service(url)
    abnormal = abnormal_url(url)
    secure = secure_http(url)
    have_ip = have_ip_address(url)
    pri_domain = extract_root_domain(url)
    region = hash_encode(get_url_region(pri_domain))
    root_dom = hash_encode(pri_domain)
    
    features = np.array([[url_len, letters, digits, special, shortened, abnormal, secure, have_ip, region, root_dom]])
    prediction = pipeline.predict(features)[0]
    probs = pipeline.predict_proba(features)[0]
    
    class_map = {0: 'Benign', 1: 'Defacement', 2: 'Phishing', 3: 'Malware'}
    pred_class = class_map.get(prediction, 'Unknown')
    confidence = max(probs)
    
    print(f"\nTest URL: {url}")
    print(f"  Prediction: {pred_class}")
    print(f"  Confidence: {confidence:.4f} ({confidence*100:.2f}%)")
    print(f"  Probabilities: Benign={probs[0]:.4f}, Defacement={probs[1]:.4f}, Phishing={probs[2]:.4f}, Malware={probs[3]:.4f}")
else:
    print("\nModel not trained - will train on first prediction request")

print("\nML Pipeline test complete!")