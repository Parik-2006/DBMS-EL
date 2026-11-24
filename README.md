# 🛡️ MaliciousBot — Malicious URL Detection System

> A Django-based Machine Learning system that analyzes URLs and classifies them as **Benign, Defacement, Phishing, or Malware**.

---

## 🎯 Project Objective

MaliciousBot automatically analyzes the structure of a URL instead of relying only on manually maintained blacklists.
It extracts URL-based features and uses a trained **Random Forest** model to predict the URL category and confidence.

---

## 🤖 How It Works

User enters URL
      ↓
Django Backend
      ↓
Feature Extraction
      ↓
Random Forest Model
      ↓
Prediction + Confidence
      ↓
Database
      ↓
Prediction History


### URL Features

- URL length
- Letters and digits
- Special characters
- URL shortener presence
- Abnormal URL check
- HTTPS usage
- IP address presence
- Region
- Root domain

---

## 🧠 Machine Learning

The project uses a **Random Forest Classifier** trained using static labeled CSV datasets.


Dataset
  ↓
Feature Extraction
  ↓
70% Training ──→ Random Forest learns patterns
  ↓
30% Testing ───→ held out (not evaluated in code)


The model classifies URLs into:

| Class | Meaning |
|-------|---------|
| 🟢 Benign | Legitimate and safe URL |
| 🔴 Defacement | Associated with unauthorized website modification |
| 🟠 Phishing | Attempts to deceive users into revealing sensitive information |
| 🔴 Malware | Associated with malicious software or harmful content |

---

## ⚙️ Tech Stack

### Backend
- Python
- Django

### Machine Learning
- Scikit-learn
- Pandas
- NumPy
- Random Forest

### Frontend
- HTML5
- CSS3
- Bootstrap
- JavaScript
- jQuery
- Django Template Language

### Database & Deployment
- MySQL (per-user tenant databases, Django ORM) + MongoDB (forensic evidence)
- WhiteNoise
- WSGI / ASGI

---

## 🗄️ Database & Application

Django's `MaliciousBot` model stores:

- User
- URL
- Prediction
- Prediction Type
- Confidence
- Timestamp

The application also provides authentication, prediction history, and an admin dashboard for viewing stored records.

---

## 🚀 Run Locally

bash
git clone <YOUR-REPOSITORY-URL>
cd <PROJECT-DIRECTORY>
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver


Open: [https://github.com/Parik-2006/diploma-project](https://github.com/Parik-2006/diploma-project)

---

## 📚 Documentation

Detailed technical documentation is consolidated under the [`docs/`](docs/) directory:

- [System Architecture & ML Pipeline Specification](docs/ARCHITECTURE.md): Comprehensive system flow, PARI 10-feature extraction, Random Forest pipeline, and fallback orchestration.
- [Database Architecture & Schema Specification](docs/DATABASE.md): MySQL dual-database routing (`maliciousbot_core`, `maliciousbot_guest`), normalized schemas, and MongoDB Atlas evidence store (`deep_analysis_cases`).
- [Nikhil Fallback Subsystem Specification](docs/NIKHIL.md): Deterministic 6-module evidence collector pipeline, community threat intel, free-only policy, and multi-family corroboration.
- [Verification & Validation Report](docs/VERIFICATION.md): historical verification notes (its `tests_local/` suite is git-ignored and not in the repository).
- [Phase 1 Implementation Report](docs/PHASE1_IMPLEMENTATION.md): tenant isolation, SSRF protection, transactional persistence, API security and hardening (MaliciousBot 2.0, branch `branch1`).

## 🧪 Tests

```bash
# Phase 1 regression suite (isolated SQLite tenants; no MySQL/MongoDB/external APIs)
python manage.py test User.tests --settings=MaliciousBot.settings_test
# Deployment / configuration suite (default settings, no database connection)
python manage.py test User.test_deployment
```

---

## 👥 Team

- Appu Gowda GC
- Bhuvan Raj H
- Ajay Kumar P

---

## 📄 License

This project is intended for educational and academic purposes.
