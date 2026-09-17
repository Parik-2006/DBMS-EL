from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse
from datetime import datetime
# Create your views here.
from django.contrib.auth.models import User,auth
from django.contrib import messages
from .models import MaliciousBot

# Always import these basic modules
import re
import string
import hashlib
from urllib.parse import urlparse
import os
import traceback

# ML imports - made optional for local development
try:
    import numpy as np
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    import ipaddress
    ML_AVAILABLE = True
except ImportError as e:
    print(f"ML dependencies not available: {e}")
    print("Running in local mode without ML features")
    ML_AVAILABLE = False

# Try to import tldextract, but have a fallback
try:
    from tldextract import extract as tld_extract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    print("Warning: tldextract not available, using fallback domain extraction")
    TLDEXTRACT_AVAILABLE = False

# Global pipeline variable
pipeline = None
model_trained = False

# Define helper functions
def hash_encode(category):
    hash_object = hashlib.md5(str(category).encode())
    return int(hash_object.hexdigest(), 16) % (10 ** 8)

def extract_root_domain(url):
    """Extract root domain from URL with fallback method"""
    try:
        if TLDEXTRACT_AVAILABLE:
            extracted = tld_extract(url)
            root_domain = extracted.domain
            return root_domain
        else:
            # Fallback: simple extraction
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            # Remove 'www.' prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
            # Get the main domain part
            parts = domain.split('.')
            if len(parts) >= 2:
                return parts[-2]
            return domain
    except Exception as e:
        print(f"Error extracting root domain from {url}: {e}")
        return "unknown"

# Define feature extraction functions if ML is available
if ML_AVAILABLE:
    def get_url_length(url):
        prefixes = ['http://', 'https://']
        for prefix in prefixes:
            if url.startswith(prefix):
                url = url[len(prefix):]
        url = url.replace('www.', '')
        return len(url)

    def count_letters(url):
        return sum(char.isalpha() for char in url)

    def count_digits(url):
        return sum(char.isdigit() for char in url)

    def count_special_chars(url):
        special_chars = set(string.punctuation)
        return sum(char in special_chars for char in url)

    def has_shortening_service(url):
        pattern = re.compile(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                            r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                            r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                            r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                            r'tr\.im|link\.zip\.net')
        match = pattern.search(url)
        return int(bool(match))

    def abnormal_url(url):
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if hostname:
            hostname = str(hostname)
            match = re.search(hostname, url)
            if match:
                return 1
        return 0

    def secure_http(url):
        scheme = urlparse(url).scheme
        if scheme == 'https':
            return 1
        else:
            return 0

    def have_ip_address(url):
        pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
                r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
                r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.' \
                r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|' \
                r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)' \
                r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|' \
                r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|' \
                r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'
        match = re.search(pattern, url)
        if match:
            return 1
        else:
            return 0

    def get_url_region(primary_domain):
        ccTLD_to_region = {
            ".ac": "Ascension Island", ".ad": "Andorra", ".ae": "United Arab Emirates", ".af": "Afghanistan",
            ".ag": "Antigua and Barbuda", ".ai": "Anguilla", ".al": "Albania", ".am": "Armenia",
            ".an": "Netherlands Antilles", ".ao": "Angola", ".aq": "Antarctica", ".ar": "Argentina",
            ".as": "American Samoa", ".at": "Austria", ".au": "Australia", ".aw": "Aruba",
            ".ax": "�& land Islands", ".az": "Azerbaijan", ".ba": "Bosnia and Herzegovina",
            ".bb": "Barbados", ".bd": "Bangladesh", ".be": "Belgium", ".bf": "Burkina Faso",
            ".bg": "Bulgaria", ".bh": "Bahrain", ".bi": "Burundi", ".bj": "Benin",
            ".bm": "Bermuda", ".bn": "Brunei Darussalam", ".bo": "Bolivia", ".br": "Brazil",
            ".bs": "Bahamas", ".bt": "Bhutan", ".bv": "Bouvet Island", ".bw": "Botswana",
            ".by": "Belarus", ".bz": "Belize", ".ca": "Canada", ".cc": "Cocos Islands",
            ".cd": "Democratic Republic of the Congo", ".cf": "Central African Republic",
            ".cg": "Republic of the Congo", ".ch": "Switzerland", ".ci": "Côte d'Ivoire",
            ".ck": "Cook Islands", ".cl": "Chile", ".cm": "Cameroon", ".cn": "China",
            ".co": "Colombia", ".cr": "Costa Rica", ".cu": "Cuba", ".cv": "Cape Verde",
            ".cw": "Curaçao", ".cx": "Christmas Island", ".cy": "Cyprus", ".cz": "Czech Republic",
            ".de": "Germany", ".dj": "Djibouti", ".dk": "Denmark", ".dm": "Dominica",
            ".do": "Dominican Republic", ".dz": "Algeria", ".ec": "Ecuador", ".ee": "Estonia",
            ".eg": "Egypt", ".er": "Eritrea", ".es": "Spain", ".et": "Ethiopia",
            ".eu": "European Union", ".fi": "Finland", ".fj": "Fiji", ".fk": "Falkland Islands",
            ".fm": "Federated States of Micronesia", ".fo": "Faroe Islands", ".fr": "France",
            ".ga": "Gabon", ".gb": "United Kingdom", ".gd": "Grenada", ".ge": "Georgia",
            ".gf": "French Guiana", ".gg": "Guernsey", ".gh": "Ghana", ".gi": "Gibraltar",
            ".gl": "Greenland", ".gm": "Gambia", ".gn": "Guinea", ".gp": "Guadeloupe",
            ".gq": "Equatorial Guinea", ".gr": "Greece", ".gs": "South Georgia and the South Sandwich Islands",
            ".gt": "Guatemala", ".gu": "Guam", ".gw": "Guinea-Bissau", ".gy": "Guyana",
            ".hk": "Hong Kong", ".hm": "Heard Island and McDonald Islands", ".hn": "Honduras",
            ".hr": "Croatia", ".ht": "Haiti", ".hu": "Hungary", ".id": "Indonesia",
            ".ie": "Ireland", ".il": "Israel", ".im": "Isle of Man", ".in": "India",
            ".io": "British Indian Ocean Territory", ".iq": "Iraq", ".ir": "Iran",
            ".is": "Iceland", ".it": "Italy", ".je": "Jersey", ".jm": "Jamaica",
            ".jo": "Jordan", ".jp": "Japan", ".ke": "Kenya", ".kg": "Kyrgyzstan",
            ".kh": "Cambodia", ".ki": "Kiribati", ".km": "Comoros", ".kn": "Saint Kitts and Nevis",
            ".kp": "North Korea", ".kr": "South Korea", ".kw": "Kuwait", ".ky": "Cayman Islands",
            ".kz": "Kazakhstan", ".la": "Laos", ".lb": "Lebanon", ".lc": "Saint Lucia",
            ".li": "Liechtenstein", ".lk": "Sri Lanka", ".lr": "Liberia", ".ls": "Lesotho",
            ".lt": "Lithuania", ".lu": "Luxembourg", ".lv": "Latvia", ".ly": "Libya",
            ".ma": "Morocco", ".mc": "Monaco", ".md": "Moldova", ".me": "Montenegro",
            ".mf": "Saint Martin", ".mg": "Madagascar", ".mh": "Marshall Islands",
            ".mk": "North Macedonia", ".ml": "Mali", ".mm": "Myanmar", ".mn": "Mongolia",
            ".mo": "Macao", ".mp": "Northern Mariana Islands", ".mq": "Martinique",
            ".mr": "Mauritania", ".ms": "Montserrat", ".mt": "Malta", ".mu": "Mauritius",
            ".mv": "Maldives", ".mw": "Malawi", ".mx": "Mexico", ".my": "Malaysia",
            ".mz": "Mozambique", ".na": "Namibia", ".nc": "New Caledonia", ".ne": "Niger",
            ".nf": "Norfolk Island", ".ng": "Nigeria", ".ni": "Nicaragua", ".nl": "Netherlands",
            ".no": "Norway", ".np": "Nepal", ".nr": "Nauru", ".nu": "Niue",
            ".nz": "New Zealand", ".om": "Oman", ".pa": "Panama", ".pe": "Peru",
            ".pf": "French Polynesia", ".pg": "Papua New Guinea", ".ph": "Philippines",
            ".pk": "Pakistan", ".pl": "Poland", ".pm": "Saint Pierre and Miquelon",
            ".pn": "Pitcairn", ".pr": "Puerto Rico", ".ps": "Palestine", ".pt": "Portugal",
            ".pw": "Palau", ".py": "Paraguay", ".qa": "Qatar", ".re": "Réunion",
            ".ro": "Romania", ".rs": "Serbia", ".ru": "Russia", ".rw": "Rwanda",
            ".sa": "Saudi Arabia", ".sb": "Solomon Islands", ".sc": "Seychelles",
            ".sd": "Sudan", ".se": "Sweden", ".sg": "Singapore", ".sh": "Saint Helena",
            ".si": "Slovenia", ".sj": "Svalbard and Jan Mayen", ".sk": "Slovakia",
            ".sl": "Sierra Leone", ".sm": "San Marino", ".sn": "Senegal", ".so": "Somalia",
            ".sr": "Suriname", ".ss": "South Sudan", ".st": "São Tomé and Príncipe",
            ".sv": "El Salvador", ".sx": "Sint Maarten", ".sy": "Syria", ".sz": "Eswatini",
            ".tc": "Turks and Caicos Islands", ".td": "Chad", ".tf": "French Southern Territories",
            ".tg": "Togo", ".th": "Thailand", ".tj": "Tajikistan", ".tk": "Tokelau",
            ".tl": "Timor-Leste", ".tm": "Turkmenistan", ".tn": "Tunisia", ".to": "Tonga",
            ".tp": "East Timor", ".tr": "Turkey", ".tt": "Trinidad and Tobago", ".tv": "Tuvalu",
            ".tw": "Taiwan", ".tz": "Tanzania", ".ua": "Ukraine", ".ug": "Uganda",
            ".uk": "United Kingdom", ".um": "United States Minor Outlying Islands", ".us": "United States",
            ".uy": "Uruguay", ".uz": "Uzbekistan", ".va": "Vatican City", ".vc": "Saint Vincent and the Grenadines",
            ".ve": "Venezuela", ".vg": "British Virgin Islands", ".vi": "U.S. Virgin Islands",
            ".vn": "Vietnam", ".vu": "Vanuatu", ".wf": "Wallis and Futuna", ".ws": "Samoa",
            ".ye": "Yemen", ".yt": "Réunion", ".yu": "Yugoslavia", ".za": "South Africa",
            ".zm": "Zambia", ".zw": "Zimbabwe"
        }

        for ccTLD in ccTLD_to_region:
            if primary_domain.endswith(ccTLD):
                return ccTLD_to_region[ccTLD]
        return "Global"

def train_model():
    global pipeline, model_trained
    if not ML_AVAILABLE:
        print("ML not available - skipping model training")
        return False

    if pipeline is not None and model_trained:
        return True  # Already trained

    try:
        # Load and preprocess data
        urls_data = pd.read_csv(r'static/dataset/Phishing.csv')
        urls_data["url_type"] = urls_data["type"].replace({
            'benign': 0,
            'defacement': 1,
            'phishing': 2,
            'malware': 3
        })

        # Apply feature extraction
        urls_data['url_len'] = urls_data['url'].apply(lambda x: get_url_length(str(x)))
        urls_data['letters_count'] = urls_data['url'].apply(lambda x: count_letters(x))
        urls_data['digits_count'] = urls_data['url'].apply(lambda x: count_digits(x))
        urls_data['special_chars_count'] = urls_data['url'].apply(lambda x: count_special_chars(x))
        urls_data['shortened'] = urls_data['url'].apply(lambda x: has_shortening_service(x))
        urls_data['abnormal_url'] = urls_data['url'].apply(lambda x: abnormal_url(x))
        urls_data['secure_http'] = urls_data['url'].apply(lambda x: secure_http(x))
        urls_data['have_ip'] = urls_data['url'].apply(lambda x: have_ip_address(x))
        urls_data['pri_domain'] = urls_data['url'].apply(lambda x: extract_root_domain(x))
        urls_data['url_region'] = urls_data['pri_domain'].apply(lambda x: hash_encode(get_url_region(str(x))))
        urls_data['root_domain'] = urls_data['pri_domain'].apply(lambda x: hash_encode(str(x)))
        urls_data.fillna(0, inplace=True)

        # Prepare training data
        x = urls_data.drop(columns=['url_type', 'url', 'pri_domain', 'type'])
        y = pd.to_numeric(urls_data['url_type'], errors='coerce')
        valid_mask = y.notna()
        x = x.loc[valid_mask]
        y = y.loc[valid_mask].astype(int)

        # Additional data cleaning
        x = x.fillna(0)
        x = x.replace([np.inf, -np.inf], 0)

        # Memory optimization: limit training data size
        max_samples = min(10000, len(x))  # Cap at 10k samples for memory efficiency
        if len(x) > max_samples:
            print(f"Limiting training data to {max_samples} samples for memory efficiency")
            indices = np.random.choice(len(x), max_samples, replace=False)
            x = x.iloc[indices]
            y = y.iloc[indices]

        print(f"Training data shape: {x.shape}")
        print(f"Target distribution: {y.value_counts()}")

        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)

        # Train the model with memory-efficient settings
        pipeline = Pipeline([
            ('classifier', RandomForestClassifier(
                n_estimators=50,  # Reduced from default 100
                max_depth=15,     # Limit tree depth
                min_samples_split=10,
                min_samples_leaf=5,
                n_jobs=1,  # Use single thread to avoid memory issues
                random_state=42
            ))
        ])

        try:
            pipeline.fit(x_train, y_train)
            model_trained = True
            print("Model trained successfully")
            return True
        except Exception as e:
            print(f"RandomForest training failed: {e}")
            # Fallback to LogisticRegression (more memory efficient)
            try:
                pipeline = Pipeline([
                    ('classifier', LogisticRegression(
                        random_state=42,
                        max_iter=1000,
                        solver='lbfgs',
                        n_jobs=1
                    ))
                ])
                pipeline.fit(x_train, y_train)
                model_trained = True
                print("Fallback model (LogisticRegression) trained successfully")
                return True
            except Exception as e2:
                print(f"Fallback model training also failed: {e2}")
                return False

    except Exception as e:
        print(f"Model training failed: {e}")
        return False

# Train the model when module loads (only in production/on Render)
import os
if os.environ.get('RENDER') or os.environ.get('PRODUCTION') or not os.path.exists('.git'):  # Detect production environment
    # Disable automatic training on module import to avoid memory issues on Render
    # Model will be trained lazily on first prediction request
    print("Running in production mode - model training will happen on first prediction request")

def index(request):
    return render(request,'index.html')

def register(request):
    if request.method == 'POST':
        try:
            print(f"[REGISTER] Starting POST request")
            
            # Get form data
            try:
                username = request.POST.get('username', '').strip()
                email = request.POST.get('email', '').strip()
                password = request.POST.get('password', '')
                password2 = request.POST.get('password2', '')
                print(f"[REGISTER] Form data received: username={username}, email={email}")
            except Exception as e:
                print(f"[REGISTER] Error getting form data: {str(e)}")
                print(traceback.format_exc())
                return render(request, 'register.html')

            # Validate inputs
            if not username or not email or not password:
                print(f"[REGISTER] Validation failed: missing fields")
                messages.error(request, 'All fields are required')
                return render(request, 'register.html')

            # Check password match
            if password != password2:
                print(f"[REGISTER] Passwords do not match")
                messages.info(request, 'Password not matching')
                return render(request, 'register.html')

            # Check email exists
            try:
                if User.objects.filter(email=email).exists():
                    print(f"[REGISTER] Email already exists: {email}")
                    messages.info(request, 'Email already exists')
                    return render(request, 'register.html')
            except Exception as e:
                print(f"[REGISTER] Error checking email: {str(e)}")
                print(traceback.format_exc())
                messages.error(request, f'Database error while checking email: {str(e)}')
                return render(request, 'register.html')

            # Check username exists
            try:
                if User.objects.filter(username=username).exists():
                    print(f"[REGISTER] Username already exists: {username}")
                    messages.info(request, 'Username already exists')
                    return render(request, 'register.html')
            except Exception as e:
                print(f"[REGISTER] Error checking username: {str(e)}")
                print(traceback.format_exc())
                messages.error(request, f'Database error while checking username: {str(e)}')
                return render(request, 'register.html')

            # Create user
            try:
                print(f"[REGISTER] Creating user: {username}")
                user = User.objects.create_user(username=username, email=email, password=password)
                user.save()
                print(f"[REGISTER] User created successfully: {username}")
                messages.success(request, 'Registration successful! Please login.')
                return HttpResponseRedirect('/login')
            except Exception as e:
                print(f"[REGISTER] Error creating user: {str(e)}")
                print(traceback.format_exc())
                messages.error(request, f'Error creating user: {str(e)}')
                return render(request, 'register.html')

        except Exception as e:
            print(f"[REGISTER] CRITICAL ERROR: {str(e)}")
            print(traceback.format_exc())
            messages.error(request, 'An error occurred during registration')
            return render(request, 'register.html')
    else:
        return render(request, 'register.html')

def login(request):
    if request.method == 'POST':
        try:
            print(f"[LOGIN] Starting POST request")
            
            try:
                username = request.POST.get('username', '').strip()
                password = request.POST.get('password', '')
                print(f"[LOGIN] Form data received: username={username}")
            except Exception as e:
                print(f"[LOGIN] Error getting form data: {str(e)}")
                print(traceback.format_exc())
                return render(request, 'login.html')

            if not username or not password:
                print(f"[LOGIN] Validation failed: missing fields")
                messages.error(request, 'Username and password are required')
                return render(request, 'login.html')

            try:
                print(f"[LOGIN] Authenticating user: {username}")
                user = auth.authenticate(username=username, password=password)
                
                if user is not None:
                    print(f"[LOGIN] Authentication successful for: {username}")
                    auth.login(request, user)
                    messages.success(request, f'Welcome back, {username}!')
                    return HttpResponseRedirect('/predict')
                else:
                    print(f"[LOGIN] Authentication failed for: {username}")
                    messages.info(request, 'Invalid credentials')
                    return render(request, 'login.html')
            except Exception as e:
                print(f"[LOGIN] Error during authentication: {str(e)}")
                print(traceback.format_exc())
                messages.error(request, f'Authentication error: {str(e)}')
                return render(request, 'login.html')
        except Exception as e:
            print(f"[LOGIN] CRITICAL ERROR: {str(e)}")
            print(traceback.format_exc())
            messages.error(request, 'An error occurred during login')
            return render(request, 'login.html')
    else:
        return render(request, 'login.html')

def adminlogin(request):
    if request.method == 'POST':
        try:
            print(f"[ADMINLOGIN] Starting POST request")
            
            try:
                username = request.POST.get('username', '').strip()
                password = request.POST.get('password', '')
                print(f"[ADMINLOGIN] Form data received: username={username}")
            except Exception as e:
                print(f"[ADMINLOGIN] Error getting form data: {str(e)}")
                print(traceback.format_exc())
                return render(request, 'adminlogin.html')

            if not username or not password:
                print(f"[ADMINLOGIN] Validation failed: missing fields")
                messages.error(request, 'Username and password are required')
                return render(request, 'adminlogin.html')

            try:
                print(f"[ADMINLOGIN] Authenticating admin user: {username}")
                user = auth.authenticate(username=username, password=password)

                if user is not None and user.is_superuser:
                    print(f"[ADMINLOGIN] Admin authentication successful for: {username}")
                    auth.login(request, user)
                    messages.success(request, f'Welcome Admin, {username}!')
                    return HttpResponseRedirect('/adminhome')
                elif user is not None:
                    print(f"[ADMINLOGIN] User authenticated but not admin: {username}")
                    messages.info(request, 'User authenticated but not an admin')
                    return render(request, 'adminlogin.html')
                else:
                    print(f"[ADMINLOGIN] Authentication failed for: {username}")
                    messages.info(request, 'Invalid credentials')
                    return render(request, 'adminlogin.html')
            except Exception as e:
                print(f"[ADMINLOGIN] Error during authentication: {str(e)}")
                print(traceback.format_exc())
                messages.error(request, f'Authentication error: {str(e)}')
                return render(request, 'adminlogin.html')
        except Exception as e:
            print(f"[ADMINLOGIN] CRITICAL ERROR: {str(e)}")
            print(traceback.format_exc())
            messages.error(request, 'An error occurred during admin login')
            return render(request, 'adminlogin.html')
    else:
        return render(request, 'adminlogin.html')

def adminhome(request):
    try:
        if request.user.is_superuser:
            data = MaliciousBot.objects.all()
            return render(request, 'adminhome.html', {'data': data})
        else:
            return HttpResponseRedirect('/adminlogin')
    except Exception as e:
        print(f"Adminhome error: {str(e)}")
        messages.error(request, 'An error occurred accessing admin home')
        return HttpResponseRedirect('/adminlogin')

def predict(request):
    if request.method == 'POST':
        try:
            print(f"[PREDICT] Starting POST request")
            
            # Get and validate URL
            try:
                url = request.POST.get('url', '').strip()
                user = request.user
                print(f"[PREDICT] URL received: {url}, User: {user}")
            except Exception as e:
                print(f"[PREDICT] Error getting form data: {str(e)}")
                print(traceback.format_exc())
                return render(request, 'predict.html')

            # Validate URL input
            if not url:
                print(f"[PREDICT] URL is empty")
                messages.error(request, 'URL cannot be empty')
                return render(request, 'predict.html')

            if not user.is_authenticated:
                print(f"[PREDICT] User not authenticated")
                messages.error(request, 'You must be logged in to make predictions')
                return HttpResponseRedirect('/login')

            prediction_result = None
            prediction_type = None
            confidence = None

            if not ML_AVAILABLE:
                # Mock response for local development
                print(f"[PREDICT] ML not available - using mock response")
                messages.warning(request, 'Running in mock mode - ML dependencies not available')
                prediction_result = "Mock prediction: URL appears safe (ML not available)"
                prediction_type = "Safe"
                confidence = "N/A"
            else:
                try:
                    # Lazy train model on first prediction if not already trained
                    if not model_trained:
                        print(f"[PREDICT] Training model on first prediction request...")
                        messages.info(request, 'Training model on first request... Please wait.')
                        if not train_model():
                            print(f"[PREDICT] Model training failed")
                            messages.error(request, 'Failed to train prediction model')
                            return render(request, 'predict.html')
                        print(f"[PREDICT] Model trained successfully")

                    # Extract features from the URL
                    try:
                        print(f"[PREDICT] Extracting features from URL")
                        url_len = get_url_length(str(url))
                        letters_count = count_letters(url)
                        digits_count = count_digits(url)
                        special_chars_count = count_special_chars(url)
                        shortened = has_shortening_service(url)
                        abnormal = abnormal_url(url)
                        secure = secure_http(url)
                        have_ip = have_ip_address(url)
                        pri_domain = extract_root_domain(url)
                        url_region = hash_encode(get_url_region(str(pri_domain)))
                        root_domain = hash_encode(str(pri_domain))
                        print(f"[PREDICT] Features extracted successfully")
                    except Exception as e:
                        error_msg = f'Error extracting URL features: {str(e)}'
                        print(f"[PREDICT] Feature extraction error: {error_msg}")
                        print(traceback.format_exc())
                        messages.error(request, error_msg)
                        prediction_result = error_msg
                        prediction_type = "Error"
                        confidence = "N/A"
                        raise

                    # Create feature array
                    try:
                        print(f"[PREDICT] Creating feature array")
                        features = np.array([[url_len, letters_count, digits_count, special_chars_count,
                                            shortened, abnormal, secure, have_ip, url_region, root_domain]])
                        print(f"[PREDICT] Feature array created: shape={features.shape}")
                    except Exception as e:
                        error_msg = f'Error creating feature array: {str(e)}'
                        print(f"[PREDICT] Feature array error: {error_msg}")
                        print(traceback.format_exc())
                        messages.error(request, error_msg)
                        prediction_result = error_msg
                        prediction_type = "Error"
                        confidence = "N/A"
                        raise

                    # Make prediction
                    if pipeline is not None and model_trained:
                        try:
                            print(f"[PREDICT] Making prediction with model")
                            prediction = pipeline.predict(features)[0]
                            prediction_proba = pipeline.predict_proba(features)[0]
                            print(f"[PREDICT] Prediction made: {prediction}, Probabilities: {prediction_proba}")

                            # Map prediction to type
                            type_mapping = {0: 'Benign', 1: 'Defacement', 2: 'Phishing', 3: 'Malware'}
                            prediction_type = type_mapping.get(prediction, 'Unknown')

                            # Calculate confidence
                            confidence = f"{max(prediction_proba) * 100:.2f}%"

                            prediction_result = f"URL classified as: {prediction_type} (Confidence: {confidence})"
                            print(f"[PREDICT] Result: {prediction_result}")
                            messages.success(request, f'Prediction completed: {prediction_type}')
                        except Exception as e:
                            error_msg = f'Error making prediction: {str(e)}'
                            print(f"[PREDICT] Prediction error: {error_msg}")
                            print(traceback.format_exc())
                            messages.error(request, error_msg)
                            prediction_result = error_msg
                            prediction_type = "Error"
                            confidence = "N/A"
                    else:
                        error_msg = "Model not trained yet. Please try again later."
                        print(f"[PREDICT] {error_msg}")
                        messages.warning(request, error_msg)
                        prediction_result = error_msg
                        prediction_type = "Unknown"
                        confidence = "N/A"

                except Exception as e:
                    if prediction_result is None:
                        error_msg = f"Unexpected error during prediction: {str(e)}"
                        print(f"[PREDICT] Prediction exception: {error_msg}")
                        print(traceback.format_exc())
                        messages.error(request, error_msg)
                        prediction_result = error_msg
                        prediction_type = "Error"
                        confidence = "N/A"

            # Save to database
            try:
                print(f"[PREDICT] Saving to database for user: {user}")
                MaliciousBot.objects.create(
                    user=user if user.is_authenticated else None,
                    url=url,
                    prediction=prediction_result or "Unknown error",
                    prediction_type=prediction_type or "Error",
                    confidence=confidence or "N/A"
                )
                print(f"[PREDICT] Successfully saved prediction to database for URL: {url}")
            except Exception as e:
                error_msg = f"Database save error: {str(e)}"
                print(f"[PREDICT] {error_msg}")
                print(traceback.format_exc())
                messages.warning(request, 'Prediction completed but could not be saved to history')

            return render(request, 'predict.html', {
                'prediction': prediction_result,
                'url': url,
                'prediction_type': prediction_type
            })

        except Exception as e:
            error_msg = f"Critical error in predict: {str(e)}"
            print(f"[PREDICT] CRITICAL ERROR: {error_msg}")
            print(traceback.format_exc())
            messages.error(request, error_msg)
            return render(request, 'predict.html', {'error': error_msg})

    else:
        return render(request, 'predict.html')

def data(request):
    if not request.user.is_authenticated:
        messages.warning(request, 'Please log in to view your predictions')
        return HttpResponseRedirect('/login')

    try:
        if not ML_AVAILABLE:
            # Mock data for local development
            messages.info(request, 'Displaying mock data - ML not fully available')
            mock_data = [
                {'url': 'https://example.com', 'prediction': 'Mock: Benign', 'prediction_type': 'Benign', 'confidence': 'N/A', 'timestamp': '2024-01-01'},
                {'url': 'http://suspicious-site.ru', 'prediction': 'Mock: Phishing', 'prediction_type': 'Phishing', 'confidence': 'N/A', 'timestamp': '2024-01-02'},
            ]
            return render(request, 'data.html', {'data': mock_data})

        try:
            user_data = MaliciousBot.objects.filter(user=request.user).order_by('-timestamp')
            data_list = []
            for item in user_data:
                try:
                    data_list.append({
                        'url': item.url,
                        'prediction': item.prediction,
                        'prediction_type': item.prediction_type,
                        'confidence': item.confidence,
                        'timestamp': item.timestamp.strftime('%Y-%m-%d %H:%M:%S') if item.timestamp else 'N/A'
                    })
                except Exception as e:
                    print(f"Error processing data item: {str(e)}")
                    continue

            if not data_list:
                messages.info(request, 'No prediction history found. Make a prediction to get started!')

            return render(request, 'data.html', {'data': data_list})

        except Exception as e:
            error_msg = f"Error retrieving prediction history: {str(e)}"
            print(error_msg)
            messages.error(request, error_msg)
            return render(request, 'data.html', {'data': [], 'error': error_msg})

    except Exception as e:
        error_msg = f"Critical error in data view: {str(e)}"
        print(error_msg)
        messages.error(request, error_msg)
        return render(request, 'data.html', {'error': error_msg})

def logout(request):
    auth.logout(request)
    return HttpResponseRedirect('/')

def health(request):
    """Health check endpoint for monitoring"""
    try:
        # Check database connectivity
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        
        db_status = "OK"
        db_message = "Database connection successful"
    except Exception as e:
        db_status = "ERROR"
        db_message = str(e)
        print(f"Health check - Database error: {db_message}")

    # Check ML availability
    ml_status = "OK" if ML_AVAILABLE else "UNAVAILABLE"
    model_status = "TRAINED" if model_trained else "NOT_TRAINED"

    # Check model training capability
    try:
        if not model_trained and ML_AVAILABLE:
            model_check = "Can train on first request"
        elif model_trained:
            model_check = "Model ready for predictions"
        else:
            model_check = "ML dependencies not available"
    except Exception as e:
        model_check = f"Model check error: {str(e)}"

    response_data = {
        "status": "healthy" if db_status == "OK" else "degraded",
        "timestamp": str(datetime.now()),
        "database": {
            "status": db_status,
            "message": db_message
        },
        "ml": {
            "available": ML_AVAILABLE,
            "status": ml_status,
            "model_trained": model_trained,
            "model_status": model_status,
            "model_check": model_check
        },
        "endpoints": {
            "predict": "/predict",
            "data": "/data",
            "register": "/register",
            "login": "/login",
            "health": "/health",
            "status": "/status"
        }
    }

    print(f"Health check performed: {response_data}")
    return JsonResponse(response_data)

def status(request):
    """Comprehensive status endpoint with detailed diagnostics"""
    try:
        import platform
        import sys
        
        # Database status
        db_status = "OK"
        db_user_count = 0
        db_prediction_count = 0
        db_message = ""

        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            db_user_count = User.objects.count()
            db_prediction_count = MaliciousBot.objects.count()
            db_message = "Database operational"
        except Exception as e:
            db_status = "ERROR"
            db_message = str(e)
            print(f"Status endpoint - Database error: {db_message}")

        # System information
        try:
            import psutil
            memory_info = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = memory_info.percent
            memory_available_mb = memory_info.available / (1024 * 1024)
        except ImportError:
            print("psutil not available - system metrics unavailable")
            cpu_percent = "N/A (psutil not installed)"
            memory_percent = "N/A (psutil not installed)"
            memory_available_mb = "N/A (psutil not installed)"
        except Exception as e:
            print(f"System metrics error: {str(e)}")
            cpu_percent = "N/A"
            memory_percent = "N/A"
            memory_available_mb = "N/A"

        # Model status
        try:
            # Estimate model size
            model_size_bytes = sys.getsizeof(pipeline) if pipeline else 0
            model_size_mb = model_size_bytes / (1024 * 1024)
        except Exception as e:
            model_size_mb = "N/A"
            print(f"Model size check error: {str(e)}")

        # Build comprehensive response
        response_data = {
            "status": "operational" if db_status == "OK" else "degraded",
            "timestamp": str(datetime.now()),
            "environment": {
                "platform": platform.system(),
                "python_version": platform.python_version(),
                "request_user": str(request.user) if request.user else "anonymous",
                "is_authenticated": request.user.is_authenticated if request.user else False
            },
            "database": {
                "status": db_status,
                "message": db_message,
                "users": db_user_count,
                "predictions": db_prediction_count
            },
            "system_resources": {
                "cpu_usage_percent": cpu_percent,
                "memory_usage_percent": memory_percent,
                "memory_available_mb": memory_available_mb if isinstance(memory_available_mb, str) else f"{memory_available_mb:.2f}"
            },
            "ml_system": {
                "ml_available": ML_AVAILABLE,
                "model_trained": model_trained,
                "model_size_mb": model_size_mb if isinstance(model_size_mb, str) else f"{model_size_mb:.2f}",
                "tldextract_available": TLDEXTRACT_AVAILABLE
            },
            "application": {
                "version": "1.0.0",
                "name": "MaliciousBot Phishing Detector",
                "deployment": "Render.com" if os.environ.get('RENDER') else "Local"
            },
            "endpoints_available": {
                "index": "/",
                "register": "/register",
                "login": "/login",
                "adminlogin": "/adminlogin",
                "predict": "/predict",
                "data": "/data",
                "adminhome": "/adminhome",
                "health": "/health",
                "status": "/status",
                "logout": "/logout"
            }
        }

        print(f"Status check performed: Application operational, DB: {db_status}, ML: {ML_AVAILABLE}")
        return JsonResponse(response_data)

    except Exception as e:
        error_msg = f"Status endpoint error: {str(e)}"
        print(error_msg)
        return JsonResponse({
            "status": "error",
            "message": error_msg,
            "timestamp": str(datetime.now())
        }, status=500)

def health(request):
    """Simple health check endpoint"""
    from django.http import JsonResponse
    from django.db import connection
    
    try:
        # Test database connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        result = cursor.fetchone()
        
        return JsonResponse({
            'status': 'ok',
            'message': 'Database connection is working',
            'database': connection.settings_dict.get('ENGINE', 'unknown')
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': f'Database error: {str(e)}',
            'database': connection.settings_dict.get('ENGINE', 'unknown')
        }, status=500)