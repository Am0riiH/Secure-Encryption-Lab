# 🔐 Secure Encryption Lab – Advanced Version

A modern, browser-based encryption lab that supports multiple encryption and encoding algorithms, plus a smart crypto analyzer that can automatically detect different encryption and encoding patterns.

Built with **HTML**, **CSS**, and **Vanilla JavaScript**.

---

## ✨ Features

### 🔹 Multi-Algorithm Encryption & Encoding
- **AES-GCM** (256-bit, browser Web Crypto API)
- **AES-CBC** (256-bit, browser Web Crypto API)
- **XOR cipher** (using a fixed derived key)
- **ROT13 encoding**
- **Caesar cipher**
- **Base64 encode/decode**
- **URL encode/decode**
- **SHA-256 hashing**

### 🔹 Smart Crypto Analyzer (Crypto AI Analyzer)
The analyzer can automatically detect:

- AES-GCM encrypted data  
- AES-CBC encrypted data  
- Base64 (single-layer and multi-layer: up to 3 layers)  
- SHA-256 hashes  
- MD5 hashes  
- JWT tokens  
- URL-encoded strings  
- XOR-encrypted strings (using the fixed key)  
- ROT13-encoded text  
- Sensitive parameters like: `token`, `key`, `auth`, `signature`  

The detection uses:
- Base64 validation and decoding attempts
- Structural analysis of IV + ciphertext
- Length and block-size heuristics
- Simple text-likelihood scoring

### 🔹 Modern UI & UX
- Tab-based interface: **Encrypt** / **Decrypt** / **Analyzer**
- Dark, cyber-style theme
- Glassmorphism-style container
- Clean form layout and responsive design
- Toast notification when copying encrypted/decrypted text

### 🔹 Fixed Master Key System
The app uses a fixed master key (derived via PBKDF2) based on a user identifier.  
This allows consistent encryption/decryption for demo and academic use, while still using modern primitives (PBKDF2 + AES-256).

> Note: For real production systems, keys must be stored and managed securely (not hard-coded).

---

## 🧪 Tabs Overview

### 1️⃣ Encrypt
- Input: plain text
- Select algorithm:
  - `AES-GCM`
  - `AES-CBC`
  - `Base64 Encode`
  - `ROT13 Encode`
  - `URL Encode`
  - `XOR Cipher`
  - `Caesar Cipher`
  - `SHA-256 (hash)`
- Output: encrypted / encoded text
- Button to copy result (with toast notification)

### 2️⃣ Decrypt
- Input: encrypted or encoded text
- Select algorithm:
  - `AES-GCM`
  - `AES-CBC`
  - `Base64 Decode`
  - `ROT13 Decode`
  - `URL Decode`
  - `XOR Cipher`
  - `Caesar Cipher`
- Output: decrypted or decoded text
- Status label:
  - ✅ `Successfully decrypted`
  - ❌ `Failed: wrong key or corrupted data`

### 3️⃣ Analyzer
- Input: any string or URL
- Output: a list of detections, for example:
  - `Base64 detected (single layer)`
  - `AES-GCM encrypted data detected`
  - `AES-CBC encrypted data detected`
  - `SHA-256 hash detected`
  - `MD5 hash detected`
  - `JWT token detected`
  - `URL encoding detected`
  - `XOR-encrypted data detected`
  - `ROT13-encoded text detected`
  - `Sensitive parameter detected (token/key/auth)`

---

## 📂 Project Structure

```text
.
├── index.html      # Main UI (Encrypt / Decrypt / Analyzer)
├── padlock.png     # icon 
├── style.css       # Dark themed styling and layout
└── script.js       # Core logic: crypto, analyzer, UI events

