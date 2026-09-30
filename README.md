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
80% Training ──→ Random Forest learns patterns
  ↓
20% Testing ───→ Model evaluation


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
- SQLite / Django ORM
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

Detailed technical documentation is consolidated under the [`docs/`](file:///P:/DBMS%20EL/diploma-project/docs/) directory:

- [System Architecture & ML Pipeline Specification](file:///P:/DBMS%20EL/diploma-project/docs/ARCHITECTURE.md): Comprehensive system flow, PARI 10-feature extraction, Random Forest pipeline, and fallback orchestration.
- [Database Architecture & Schema Specification](file:///P:/DBMS%20EL/diploma-project/docs/DATABASE.md): MySQL dual-database routing (`maliciousbot_core`, `maliciousbot_guest`), normalized schemas, and MongoDB Atlas evidence store (`deep_analysis_cases`).
- [Nikhil Fallback Subsystem Specification](file:///P:/DBMS%20EL/diploma-project/docs/NIKHIL.md): Deterministic 6-module evidence collector pipeline, community threat intel, free-only policy, and multi-family corroboration.
- [Verification & Validation Report](file:///P:/DBMS%20EL/diploma-project/docs/VERIFICATION.md): Full automated test suite results (145 tests), real runtime scan logs, and security guardrail verification.

---

## 👥 Team

- Appu Gowda GC
- Bhuvan Raj H
- Ajay Kumar P

---

## 📄 License

This project is intended for educational and academic purposes.
