import streamlit as st
import json
import base64
from credit_card_des_secure import (
    luhn_make,
    luhn_validate,
    encrypt_pan,
    decrypt_pan,
    load_records,
    append_record,
    mask_pan,
)

STORAGE_FILE = "records.json"

# ---- Streamlit page setup ----
st.set_page_config(
    page_title="Credit Card Encryption & Decryption (DES)",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.title("💳 Credit Card Encryption & Decryption using DES")
st.caption("Cybersecurity Project • Bharati Vidyapeeth College of Engineering, Pune")

# ---- Sidebar navigation ----
page = st.sidebar.radio("Select Function", ["🔹 Generate PAN", "🔹 Encrypt", "🔹 List Records", "🔹 Decrypt", "📘 About"])

# ---- Helper to refresh storage ----
def refresh_records():
    try:
        return load_records(STORAGE_FILE)
    except Exception:
        return []

# ---- Generate synthetic PAN ----
if page == "🔹 Generate PAN":
    st.header("Generate Synthetic PAN (Luhn-valid)")
    if st.button("Generate PAN"):
        pan = luhn_make()
        st.success(f"Generated PAN: {pan}")

# ---- Encrypt ----
elif page == "🔹 Encrypt":
    st.header("Encrypt Credit Card Number")
    with st.form("encrypt_form"):
        pan = st.text_input("Enter synthetic PAN (digits only):")
        passphrase = st.text_input("Enter passphrase to derive key:", type="password")
        submitted = st.form_submit_button("Encrypt and Save")

    if submitted:
        if not pan.isdigit():
            st.error("PAN must contain digits only.")
        else:
            if not luhn_validate(pan):
                st.warning("PAN does not pass Luhn validation. Use synthetic or correct PAN.")
            try:
                payload = encrypt_pan(pan, passphrase)
                append_record(payload, STORAGE_FILE)
                st.success("✅ Encrypted record appended to records.json")
            except Exception as e:
                st.error(f"Encryption failed: {e}")

# ---- List Records ----
elif page == "🔹 List Records":
    st.header("Stored Records (Encrypted)")
    records = refresh_records()
    if not records:
        st.info("No records found.")
    else:
        st.write(f"**Found {len(records)} record(s).**")
        for i, rec in enumerate(records, start=1):
            st.code(
                f"[{i}] salt_len={len(base64.b64decode(rec['salt']))} "
                f"iv_len={len(base64.b64decode(rec['iv']))} "
                f"ct_len={len(base64.b64decode(rec['ct']))} "
                f"mac_len={len(base64.b64decode(rec['mac']))}"
            )

# ---- Decrypt ----
elif page == "🔹 Decrypt":
    st.header("Decrypt Stored Record")
    records = refresh_records()
    if not records:
        st.info("No records found.")
    else:
        record_index = st.number_input(
            "Enter record index to decrypt:",
            min_value=1,
            max_value=len(records),
            step=1,
            format="%d"
        )
        passphrase = st.text_input("Enter passphrase:", type="password")
        if st.button("Decrypt"):
            payload = records[record_index - 1]
            try:
                pan = decrypt_pan(payload, passphrase)
                st.success("✅ Decryption Successful!")
                st.text(f"Decrypted PAN: {pan}")
                st.text(f"Masked PAN: {mask_pan(pan)}")
            except Exception as e:
                st.error(f"Decryption failed: {e}")

# ---- About ----
elif page == "📘 About":
    st.header("About This Project")
    st.markdown("""
    **Project Title:** Credit Card Encryption and Decryption using DES  
    **Language:** Python  
    **Framework:** Streamlit  
    **Algorithm:** DES (CBC mode) with PBKDF2 + HMAC-SHA256  
    **Students:** Manika Jain, Aastha Gupta, Trisha Hali  
    **College:** Bharati Vidyapeeth College of Engineering, Pune  
    
    ---
    **Features:**
    - DES Encryption/Decryption  
    - PBKDF2 Password-based Key Derivation  
    - HMAC Integrity Check  
    - JSON Record Storage  
    - Luhn Algorithm Validation  
    - Secure Masked Output  
    - Tamper Detection  
    """)

    st.markdown("© 2025 | Educational use only. Do not use DES in real systems.")


