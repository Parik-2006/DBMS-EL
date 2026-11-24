from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse
from django.views.decorators.http import require_POST
from datetime import datetime
import logging
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
import threading

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
_model_training_lock = threading.Lock()

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

    with _model_training_lock:
        if pipeline is not None and model_trained:
            return True
        return _do_train_model()

def _do_train_model():
    global pipeline, model_trained
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

logger = logging.getLogger(__name__)

URL_MAX_LENGTH = 500  # pari_url.url column length (strict SQL mode rejects longer values)
_URL_FORBIDDEN_CHARS = re.compile(r'[\x00-\x20\x7f]')
_GENERIC_ERROR = 'An internal error occurred while processing your request. Please try again.'


def _validate_submitted_url(url):
    """Light submission validation. Outbound safety is enforced separately by the collectors."""
    if not url:
        return 'URL cannot be empty'
    if len(url) > URL_MAX_LENGTH:
        return f'URL is too long (maximum {URL_MAX_LENGTH} characters)'
    if _URL_FORBIDDEN_CHARS.search(url):
        return 'URL must not contain whitespace or control characters'
    if '://' in url:
        scheme = url.split('://', 1)[0].lower()
        if scheme not in ('http', 'https'):
            return 'Only http:// and https:// URLs can be analysed'
    from User.services.domain_normalization import normalize_url
    if not normalize_url(url).hostname:
        return 'URL must include a valid host name'
    return None


def _too_many_requests(request, template, message, retry_after, context=None):
    messages.error(request, message)
    response = render(request, template, context or {})
    response.status_code = 429
    response['Retry-After'] = str(retry_after)
    return response


def index(request):
    return render(request, 'index.html')


def register(request):
    if request.method != 'POST':
        return render(request, 'register.html')

    from django.contrib.auth.password_validation import validate_password
    from django.contrib.auth.validators import UnicodeUsernameValidator
    from django.core.exceptions import ValidationError
    from django.core.validators import validate_email
    from User.security import ratelimit

    allowed, retry_after = ratelimit.hit('register', f"ip:{ratelimit.client_ip(request)}")
    if not allowed:
        return _too_many_requests(request, 'register.html',
                                  'Too many registration attempts. Please try again later.', retry_after)

    username = request.POST.get('username', '').strip()
    email = request.POST.get('email', '').strip()
    password = request.POST.get('password', '')
    password2 = request.POST.get('password2', '')

    if not username or not email or not password:
        messages.error(request, 'All fields are required')
        return render(request, 'register.html')
    try:
        if len(username) > 150:
            raise ValidationError('Username is too long')
        UnicodeUsernameValidator()(username)
    except ValidationError:
        messages.error(request, 'Username may contain only letters, digits and @/./+/-/_ (max 150 characters)')
        return render(request, 'register.html')
    try:
        validate_email(email)
    except ValidationError:
        messages.error(request, 'Enter a valid email address')
        return render(request, 'register.html')
    if password != password2:
        messages.info(request, 'Password not matching')
        return render(request, 'register.html')
    try:
        validate_password(password, user=User(username=username, email=email))
    except ValidationError as exc:
        for msg in exc.messages:
            messages.error(request, msg)
        return render(request, 'register.html')

    try:
        exists = (User.objects.filter(username__iexact=username).exists()
                  or User.objects.filter(email__iexact=email).exists())
    except Exception as exc:
        logger.error("[REGISTER] account lookup failed: %s", type(exc).__name__)
        messages.error(request, _GENERIC_ERROR)
        return render(request, 'register.html')
    if exists:
        # One generic message for username OR email collisions (limits account enumeration).
        messages.info(request, 'An account with these details already exists. Please choose different details or log in.')
        return render(request, 'register.html')

    created_user = None
    try:
        created_user = User.objects.create_user(username=username, email=email, password=password)
        from User.db_manager import ensure_user_database
        ensure_user_database(created_user)
        logger.info("[REGISTER] account created and workspace provisioned (user id %s)",
                    getattr(created_user, 'id', '?'))
        messages.success(request, 'Registration successful! Please login.')
        return HttpResponseRedirect('/login')
    except Exception as exc:
        logger.error("[REGISTER] account/workspace provisioning failed: %s", type(exc).__name__)
        if created_user is not None and getattr(created_user, 'id', None):
            try:
                created_user.delete()
            except Exception:
                logger.error("[REGISTER] could not roll back partially created account")
        messages.error(request, 'Error creating account and provisioning workspace. Please try again.')
        return render(request, 'register.html')


def _rate_limited_login(request, username, template):
    """Shared IP + username throttling for both login forms. Returns a response or None."""
    from User.security import ratelimit
    ip_ok, ip_retry = ratelimit.hit('login_ip', f"ip:{ratelimit.client_ip(request)}")
    if not ip_ok:
        return _too_many_requests(request, template, 'Too many login attempts. Please try again later.', ip_retry)
    if username and ratelimit.peek_exceeded('login_user', f"user:{username.lower()}"):
        return _too_many_requests(request, template, 'Too many login attempts. Please try again later.', 60)
    return None


def _record_login_failure(username):
    from User.security import ratelimit
    if username:
        ratelimit.hit('login_user', f"user:{username.lower()}")


def login(request):
    if request.method != 'POST':
        return render(request, 'login.html')
    username = request.POST.get('username', '').strip()
    password = request.POST.get('password', '')
    if not username or not password:
        messages.error(request, 'Username and password are required')
        return render(request, 'login.html')
    limited = _rate_limited_login(request, username, 'login.html')
    if limited:
        return limited
    try:
        user = auth.authenticate(request, username=username, password=password)
    except Exception as exc:
        logger.error("[LOGIN] authentication backend error: %s", type(exc).__name__)
        messages.error(request, _GENERIC_ERROR)
        return render(request, 'login.html')
    if user is None:
        _record_login_failure(username)
        messages.info(request, 'Invalid username or password')
        return render(request, 'login.html')
    auth.login(request, user)
    messages.success(request, f'Welcome back, {user.username}!')
    return HttpResponseRedirect('/predict')


def adminlogin(request):
    if request.method != 'POST':
        return render(request, 'adminlogin.html')
    username = request.POST.get('username', '').strip()
    password = request.POST.get('password', '')
    if not username or not password:
        messages.error(request, 'Username and password are required')
        return render(request, 'adminlogin.html')
    limited = _rate_limited_login(request, username, 'adminlogin.html')
    if limited:
        return limited
    try:
        user = auth.authenticate(request, username=username, password=password)
    except Exception as exc:
        logger.error("[ADMINLOGIN] authentication backend error: %s", type(exc).__name__)
        messages.error(request, _GENERIC_ERROR)
        return render(request, 'adminlogin.html')
    if user is None or not user.is_superuser:
        # Same message for wrong credentials and non-admin accounts.
        _record_login_failure(username)
        messages.info(request, 'Invalid administrator credentials')
        return render(request, 'adminlogin.html')
    auth.login(request, user)
    messages.success(request, f'Welcome Admin, {user.username}!')
    return HttpResponseRedirect('/adminhome')


def adminhome(request):
    """
    Administrator dashboard: read-only, tenant-aware overview.

    Iterates the active tenants in user_database_registry (core DB) and reads
    each tenant's recent history rows through an explicit connection alias
    (no provisioning, no writes). Only superusers may access it.
    """
    if not (request.user.is_authenticated and request.user.is_superuser):
        return HttpResponseRedirect('/adminlogin')

    from User.models import UserDatabaseRegistry
    from User.security.tenancy import resolve_existing_tenant_alias

    per_tenant_limit = 50
    rows = []
    tenants = []
    try:
        registries = list(UserDatabaseRegistry.objects.using('default').filter(status='active').order_by('user_id')[:200])
    except Exception as exc:
        logger.error("[ADMIN] registry lookup failed: %s", type(exc).__name__)
        registries = []
        messages.error(request, 'Could not load the tenant registry')

    for reg in registries:
        tenant_id = f"user:{reg.user_id}"
        try:
            alias = resolve_existing_tenant_alias(tenant_id)
            if alias is None:
                continue
            entries = list(MaliciousBot.objects.using(alias).order_by('-timestamp')[:per_tenant_limit])
        except Exception as exc:
            logger.warning("[ADMIN] tenant %s unavailable: %s", reg.user_id, type(exc).__name__)
            tenants.append({'username': reg.username, 'database': reg.database_name, 'count': None})
            continue
        tenants.append({'username': reg.username, 'database': reg.database_name, 'count': len(entries)})
        for entry in entries:
            rows.append({
                'id': entry.id,
                'tenant': reg.username,
                'url': entry.url,
                'prediction_type': entry.prediction_type,
                'confidence': entry.confidence,
                'timestamp': entry.timestamp,
            })
    rows = sorted(rows, key=lambda r: r['timestamp'].timestamp() if r['timestamp'] else 0, reverse=True)
    return render(request, 'adminhome.html', {'data': rows, 'tenants': tenants})


def predict(request):
    if request.method != 'POST':
        return render(request, 'predict.html')

    url = request.POST.get('url', '').strip()
    user = request.user
    if not user.is_authenticated:
        messages.error(request, 'You must be logged in to make predictions')
        return HttpResponseRedirect('/login')

    error = _validate_submitted_url(url)
    if error:
        messages.error(request, error)
        response = render(request, 'predict.html', {'url': url[:URL_MAX_LENGTH]})
        response.status_code = 400
        return response

    from User.security import ratelimit
    allowed, retry_after = ratelimit.hit('scan', f"user:{user.id}")
    if not allowed:
        return _too_many_requests(request, 'predict.html', 'Scan rate limit reached. Please wait before submitting more URLs.',
                                  retry_after)

    if not ML_AVAILABLE:
        # Truthful status: no fabricated "Safe" result when the ML engine is missing.
        logger.error("[PREDICT] ML dependencies unavailable; scan not performed")
        messages.error(request, 'The ML analysis engine is unavailable on this server. No classification was produced.')
        response = render(request, 'predict.html', {'url': url, 'error': 'ML engine unavailable'})
        response.status_code = 503
        return response

    if not model_trained:
        messages.info(request, 'Training model on first request... Please wait.')
        if not train_model():
            logger.error("[PREDICT] model training failed")
            messages.error(request, 'Failed to train prediction model')
            response = render(request, 'predict.html', {'url': url})
            response.status_code = 503
            return response

    from User.models import Domain, URL
    from User.services import get_confidence_threshold
    from User.services.domain_normalization import normalize_url
    from User.services.fallback_service import FallbackIntegrationService
    from User.services.ml_service import MLPredictionService
    from User.services.nikhil.nikhil_service import NikhilService
    from User.security.tenancy import tenant_id_for_alias

    alias = getattr(request, 'user_db', None) or 'guest_db'
    tenant_id = getattr(request, 'tenant_id', None) or tenant_id_for_alias(alias)
    scan = None
    try:
        # 1. Normalize Domain and URL (registered-domain storage, public suffix in tld)
        norm = normalize_url(url)
        domain_obj, _ = Domain.objects.using(alias).get_or_create(
            domain_name=norm.registered_domain[:255],
            defaults={'tld': (norm.suffix or None) and norm.suffix[:63]},
        )
        if norm.suffix and not domain_obj.tld:
            Domain.objects.using(alias).filter(id=domain_obj.id).update(tld=norm.suffix[:63])
        url_obj, _ = URL.objects.using(alias).get_or_create(
            url=url, defaults={'domain': domain_obj, 'source': 'USER_SCAN'})
        if url_obj.domain_id is None:
            URL.objects.using(alias).filter(id=url_obj.id).update(domain=domain_obj)

        # 2. Scan record + 3. PARI prediction (atomic on the tenant DB)
        scan = MLPredictionService.create_scan_record(url_obj, user=user, db=alias)
        pred_data = MLPredictionService.make_prediction(pipeline, url, scan, db=alias)
        initial_prediction = pred_data['predicted_class']
        initial_confidence_float = pred_data['confidence']
        initial_confidence_str = f"{initial_confidence_float * 100:.2f}%"
        is_confident = pred_data['is_confident']
        threshold = get_confidence_threshold()
        logger.info("[PREDICT] scan %s: %s @ %s (threshold %.2f, confident=%s)",
                    scan.id, initial_prediction, initial_confidence_str, threshold, is_confident)

        context = {'url': url, 'scan_id': scan.id}

        if is_confident:
            prediction_result = f"URL classified as: {initial_prediction} (Confidence: {initial_confidence_str})"
            messages.success(request, f'Prediction completed: {initial_prediction} ({initial_confidence_str})')
            MaliciousBot.objects.using(alias).create(
                user=user, url=url, scan=scan, prediction=prediction_result,
                prediction_type=initial_prediction, confidence=initial_confidence_str)
            context.update({
                'is_confident': True,
                'status': 'CONFIDENT',
                'prediction': prediction_result,
                'prediction_type': initial_prediction,
                'confidence': initial_confidence_str,
                'model_name': 'RandomForest',
            })
            return render(request, 'predict.html', context)

        # UNCERTAIN -> Nikhil fallback (explicit tenant identity everywhere)
        FallbackIntegrationService.mark_deep_analysis_started(scan, db=alias)
        try:
            analysis_result = NikhilService().analyze_uncertain_url({
                'scan_id': scan.id,
                'url': url,
                'initial_prediction': initial_prediction,
                'initial_confidence': initial_confidence_float,
                'scan_status': 'DEEP_ANALYSIS',
                'pari_features': pred_data.get('pari_features'),
                'db_alias': alias,
                'tenant_id': tenant_id,
                'investigation_id': str(scan.investigation_id),
            })
        except Exception as exc:
            logger.error("[PREDICT] deep analysis failed for scan %s: %s", scan.id, type(exc).__name__)
            FallbackIntegrationService.mark_scan_failed(scan.id, f"Deep analysis failed: {type(exc).__name__}", db=alias)
            messages.error(request, 'Deep analysis could not be completed. The initial ML prediction was preserved.')
            context.update({'is_confident': False, 'status': 'FAILED', 'initial_prediction': initial_prediction,
                            'initial_confidence': initial_confidence_str, 'error': 'Deep analysis failed'})
            return render(request, 'predict.html', context)

        fallback_processed = FallbackIntegrationService.process_fallback_result(
            analysis_result, db_alias=alias, tenant_id=tenant_id)
        if not fallback_processed.get('success'):
            logger.error("[PREDICT] fallback persistence failed for scan %s: %s", scan.id,
                         fallback_processed.get('errors'))
            FallbackIntegrationService.mark_scan_failed(
                scan.id, (fallback_processed.get('errors') or ['Fallback persistence failed'])[0], db=alias)
            messages.error(request, 'The deep-analysis result could not be saved; the scan is marked as failed.')

        final_classification = analysis_result.get('final_classification', 'Unknown')
        risk_level = analysis_result.get('risk_level', 'MEDIUM')
        risk_score = analysis_result.get('risk_score', 0.5)
        visual_snapshot = (analysis_result.get('evidence_data', {}).get('visual', {}) or {}).get('screenshot_reference')

        prediction_result = f"Deep Analysis Result: {final_classification} (Risk: {risk_level}, Score: {risk_score:.2f})"
        if fallback_processed.get('success'):
            messages.info(request, f'Deep analysis complete: {final_classification} '
                                   f'(Initial: {initial_prediction} @ {initial_confidence_str})')
            MaliciousBot.objects.using(alias).create(
                user=user, url=url, scan=scan,
                prediction=f"Initial: {initial_prediction} ({initial_confidence_str}) → Fallback: {final_classification} "
                           f"(Risk: {risk_level}, Score: {risk_score:.2f})",
                prediction_type=final_classification,
                confidence=f"Initial: {initial_confidence_str}, Risk: {risk_level}")

        context.update({
            'is_confident': False,
            'status': 'COMPLETED' if fallback_processed.get('success') else 'FAILED',
            'fallback_invoked': True,
            'initial_prediction': initial_prediction,
            'initial_confidence': initial_confidence_str,
            'final_classification': final_classification,
            'risk_level': risk_level,
            'risk_score': f"{risk_score:.2f}",
            'evidence_summary': analysis_result.get('evidence_summary', ''),
            'threat_indicators': analysis_result.get('threat_indicators', []),
            'mongo_ref': analysis_result.get('mongo_document_reference'),
            'forensic_status': analysis_result.get('forensic_status'),
            'corroboration': analysis_result.get('corroboration', {}),
            'module_statuses': analysis_result.get('module_statuses', {}),
            'evidence_breakdown': analysis_result.get('evidence_breakdown', {}),
            'ai_display': analysis_result.get('ai_display', {}),
            'visual_snapshot': visual_snapshot,
            'threat_intel_display': analysis_result.get('threat_intel_display', {}),
            'prediction': prediction_result,
            'prediction_type': final_classification,
            'confidence': f"Initial: {initial_confidence_str} (Below {threshold * 100:.0f}% threshold)",
        })
        return render(request, 'predict.html', context)

    except Exception as exc:
        logger.error("[PREDICT] unexpected failure: %s", type(exc).__name__)
        if scan is not None:
            FallbackIntegrationService.mark_scan_failed(scan.id, f"Unexpected failure: {type(exc).__name__}", db=alias)
        messages.error(request, _GENERIC_ERROR)
        response = render(request, 'predict.html', {'error': 'Scan failed'})
        response.status_code = 500
        return response


def _threat_intel_badges(evidence_doc):
    ti_doc = (evidence_doc or {}).get('threat_intelligence') or {}
    sources = ti_doc.get('sources', {}) or {}
    local_sql = sources.get('local_sql', {}) or {}
    trusted = sources.get('trusted_domain', {}) or {}
    malicious = local_sql.get('known_malicious_in_domain', 0) or 0
    return {
        'threatfox': (sources.get('threatfox', {}) or {}).get('status', 'NO_MATCH'),
        'urlhaus': (sources.get('urlhaus', {}) or {}).get('status', 'NO_MATCH'),
        'abuseipdb': f"{(sources.get('abuseipdb', {}) or {}).get('abuse_confidence_score', 0)}% abuse confidence",
        'local_sql': f"{malicious} historical malicious" if malicious > 0 else "No historical indicator",
        'trusted_domain': trusted.get('category') or ("Verified" if trusted.get('is_known') else "Not Listed"),
    }


def data(request):
    if not request.user.is_authenticated:
        messages.warning(request, 'Please log in to view your predictions')
        return HttpResponseRedirect('/login')

    from User.models import HistoryClearEvent
    from User.security.tenancy import tenant_id_for_alias
    from User.services.fallback_service import FallbackIntegrationService

    alias = getattr(request, 'user_db', None) or 'guest_db'
    tenant_id = getattr(request, 'tenant_id', None) or tenant_id_for_alias(alias)

    # Recover scans interrupted by worker restarts/timeouts so they never stay pending.
    try:
        FallbackIntegrationService.recover_stale_scans(db=alias)
    except Exception as exc:
        logger.warning("[HISTORY] stale-scan recovery skipped: %s", type(exc).__name__)

    try:
        latest_clear = HistoryClearEvent.objects.using(alias).order_by('-cleared_at').first()
        history = MaliciousBot.objects.using(alias).select_related('scan').order_by('-timestamp')
        if latest_clear:
            history = history.filter(timestamp__gt=latest_clear.cleared_at)
    except Exception as exc:
        logger.error("[HISTORY] history query failed: %s", type(exc).__name__)
        messages.error(request, 'Could not load prediction history')
        return render(request, 'data.html', {'data': [], 'error': 'history unavailable'})

    data_list = []
    mongo_repo = None
    for item in history:
        ti_info = None
        scan = item.scan  # exact scan that produced this row (NULL for legacy rows)
        if scan is not None and scan.fallback_model:
            try:
                if mongo_repo is None:
                    from User.services.nikhil.mongodb_repository import MongoDBRepository
                    mongo_repo = MongoDBRepository()
                ti_info = _threat_intel_badges(mongo_repo.get_evidence(scan.id, tenant_id=tenant_id))
            except Exception as exc:
                # Evidence lookup problems never hide the history row itself.
                logger.debug("[HISTORY] TI details unavailable for history row %s: %s", item.id, type(exc).__name__)
                ti_info = None
        data_list.append({
            'id': item.id,
            'url': item.url,
            'prediction': item.prediction,
            'prediction_type': item.prediction_type,
            'confidence': item.confidence,
            'timestamp': item.timestamp.strftime('%Y-%m-%d %H:%M:%S') if item.timestamp else 'N/A',
            'threat_intel': ti_info,
            'scan_status': scan.status if scan is not None else None,
            'forensic_status': scan.forensic_status if scan is not None else None,
        })

    if not data_list:
        messages.info(request, 'No prediction history found. Make a prediction to get started!')
    return render(request, 'data.html', {'data': data_list})


@require_POST
def clear_history(request):
    """
    Non-destructive history visibility reset.
    Does NOT delete any record from MySQL or MongoDB.
    """
    if not request.user.is_authenticated:
        messages.warning(request, 'Please log in to clear history view')
        return HttpResponseRedirect('/login')
    from django.utils import timezone
    from User.models import HistoryClearEvent
    alias = getattr(request, 'user_db', None) or 'guest_db'
    HistoryClearEvent.objects.using(alias).create(user_id=request.user.id, cleared_at=timezone.now())
    messages.info(request, "History cleared from view. Your records remain stored securely.")
    return HttpResponseRedirect('/data')


@require_POST
def logout(request):
    auth.logout(request)
    return HttpResponseRedirect('/')


def health(request):
    """Public liveness/readiness probe: core DB reachability only (no details)."""
    from django.db import connection

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception as e:
        logger.error("Health check - core database error: %s", type(e).__name__)
        return JsonResponse({
            'status': 'error',
            'message': 'Database unavailable',
            'database': connection.settings_dict.get('ENGINE', 'unknown'),
        }, status=503)

    return JsonResponse({
        'status': 'ok',
        'message': 'Database connection is working',
        'database': connection.settings_dict.get('ENGINE', 'unknown'),
    })


def status(request):
    """
    Status endpoint. Anonymous / non-staff callers get only an overall status;
    detailed diagnostics (counts, platform, ML state, resources) require a
    staff account. Exception details are never returned.
    """
    from django.db import connection

    db_status = "OK"
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
    except Exception as e:
        db_status = "ERROR"
        logger.error("Status endpoint - core database error: %s", type(e).__name__)

    overall = "operational" if db_status == "OK" else "degraded"
    payload = {"status": overall, "timestamp": str(datetime.now()), "database": {"status": db_status}}

    if not (request.user.is_authenticated and request.user.is_staff):
        return JsonResponse(payload)

    try:
        import platform
        import sys
        if db_status == "OK":
            try:
                payload["database"]["users"] = User.objects.count()
                payload["database"]["predictions"] = MaliciousBot.objects.count()
            except Exception as e:
                logger.error("Status endpoint - count query failed: %s", type(e).__name__)
        try:
            import psutil
            memory_info = psutil.virtual_memory()
            resources = {
                "cpu_usage_percent": psutil.cpu_percent(interval=0.1),
                "memory_usage_percent": memory_info.percent,
                "memory_available_mb": f"{memory_info.available / (1024 * 1024):.2f}",
            }
        except ImportError:
            resources = {"cpu_usage_percent": "N/A (psutil not installed)",
                         "memory_usage_percent": "N/A (psutil not installed)",
                         "memory_available_mb": "N/A (psutil not installed)"}
        payload.update({
            "environment": {"platform": platform.system(), "python_version": platform.python_version()},
            "system_resources": resources,
            "ml_system": {
                "ml_available": ML_AVAILABLE,
                "model_trained": model_trained,
                "model_size_mb": f"{(sys.getsizeof(pipeline) if pipeline else 0) / (1024 * 1024):.2f}",
                "tldextract_available": TLDEXTRACT_AVAILABLE,
            },
            "application": {
                "version": "1.0.0",
                "name": "MaliciousBot Phishing Detector",
                "deployment": "Render.com" if os.environ.get('RENDER') else "Local",
            },
        })
        return JsonResponse(payload)
    except Exception as e:
        logger.error("Status endpoint error: %s", type(e).__name__)
        return JsonResponse({"status": "error", "message": "Status unavailable",
                             "timestamp": str(datetime.now())}, status=500)
