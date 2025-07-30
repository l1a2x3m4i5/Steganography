# 🔐 Media Encryption & Steganography Web App

This is a **Flask-based web application** that allows users to **encrypt messages** using AES or DES algorithms and **hide encrypted messages inside images or audio files** using LSB steganography. It also supports **secure decryption**, key expiration, and file expiry features for added protection.

---

## 🚀 Features

- AES & DES encryption/decryption for text messages.
- Hide and retrieve messages from image files (`.png`, `.jpg`, `.jpeg`).
- Hide and retrieve messages from audio files (`.wav`).
- Secure, time-limited key generation (3 minutes expiry).
- File auto-expiration after 5 minutes.
- Input validation and error handling with flash messages.
- Encrypted file and key download support.

---

## Tech Stack

- **Frontend:** HTML (Jinja2 templates via Flask)
- **Backend:** Python, Flask
- **Crypto Libraries:** `pycryptodome` for AES/DES
- **Image Handling:** `Pillow`
- **Audio Handling:** `wave` module

---

## Project Structure

```bash
├── app.py                  # Main Flask app
├── uploads/                # Folder for uploaded/encrypted files
├── templates/
│   ├── base.html           # Home page
│   ├── encryptMedia.html   # Encryption form
│   └── decryptMedia.html   # Decryption form
├── static/                 # Optional: CSS, JS if added
└── README.md               # Project documentation

## Installation of dependencies
-pip install Flask
-pip install Pillow
-pip install pycryptodome

## Run the app
-python app.py
