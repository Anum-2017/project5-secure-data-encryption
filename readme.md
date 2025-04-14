# 🔐 Secure Data Encryption System

🚀 **Live App**: https://project5-secure-data-encryption.streamlit.app/

The **Secure Data Encryption System** is a web-based application built with **Streamlit** that enables users to securely **register**, **log in**, **encrypt sensitive data**, and **retrieve it** using a private passkey. It uses **SHA-256 hashing**, **Fernet symmetric encryption**, and **SQLite** to ensure data privacy, controlled access, and persistence.

---

## 📌 Features

### 🔐 User Registration & Login
- Secure password storage with **SHA-256 hashing**
- Prevents duplicate username registration
- Brute-force protection via **login attempt limits**

### 📦 Data Encryption
- Encrypt any text input using **Fernet symmetric encryption**
- Assign a custom **label** and **passkey** to each encrypted entry
- Passkey-protected access ensures only you can decrypt your data

### 🔍 Data Retrieval
- Access your encrypted data via **label** and **correct passkey**
- Dashboard to view all encrypted entries you've created

### 📊 User Dashboard
- See session statistics (e.g., number of encrypted & retrieved items)
- Manage encrypted items in a personalized user interface

### 🔒 Security Highlights
- **SHA-256** for hashing passwords (via `hashlib`)
- **Fernet** encryption (from `cryptography` package) for secure symmetric encryption
- **SQLite** as a lightweight and persistent data store
- **Session tracking** and brute-force protection

---

## 🛠️ Tech Stack

| Layer       | Tech                     |
|-------------|--------------------------|
| Frontend    | Streamlit                |
| Backend     | Python                   |
| Database    | SQLite                   |
| Encryption  | Fernet (Cryptography)    |
| Hashing     | SHA-256 (hashlib)        |
