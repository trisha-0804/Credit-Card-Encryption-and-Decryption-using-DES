# Credit Card Encryption and Decryption using DES

Cyber Security project demonstrating encryption of credit card numbers using DES algorithm.

## Features
- DES Encryption (CBC Mode)
- PBKDF2 Key Derivation
- HMAC-SHA256 Integrity Verification
- Luhn Algorithm for PAN validation
- JSON Secure Storage
- Streamlit Interface

## Technologies
Python  
PyCryptodome  
Streamlit  

## Files
credit_card_des_secure.py – encryption and decryption logic  
ui.py – Streamlit interface  
records.json – encrypted data storage  

## Run Project

Install dependencies:

pip install -r requirements.txt

Run Streamlit app:

streamlit run ui.py

## Educational Purpose
This project demonstrates cryptographic techniques for protecting credit card data. DES is used for educational purposes only.
