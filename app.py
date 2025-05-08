import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet, InvalidToken
import base64

# 🔐 Generate key from passkey (not static)
def generate_key(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# 📁 File to store encrypted data
DATA_FILE = "data.json"

# 🧠 Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# ADMIN PASSWORD (visible in UI for other users)
ADMIN_PASSWORD = "secure@123"  # Changed to more secure password

# 📥 Load existing data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

# 💾 Save data
def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

# 🔐 Encrypt data using passkey-based key
def encrypt_data(text, passkey):
    key = generate_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        key = generate_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except InvalidToken:
        st.session_state.failed_attempts += 1
        return None

# 🌐 Custom UI Components
def purple_footer():
    st.markdown(f"""
    <style>
    .footer {{
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #6a0dad;
        color: white;
        text-align: center;
        padding: 10px;
        font-family: Arial, sans-serif;
    }}
    .footer a {{
        color: white;
        text-decoration: none;
    }}
    .footer a:hover {{
        text-decoration: underline;
    }}
    </style>
    <div class="footer">
        <p>🔒 Secure Data System | © 2023 | Made by Ghaniya Khan | 
        <a href="https://github.com/ghaniya08" target="_blank">GitHub</a></p>
        <p>Admin Password: <strong>{ADMIN_PASSWORD}</strong></p>
    </div>
    """, unsafe_allow_html=True)

def page_header(title):
    st.markdown(f"""
    <style>
    .header {{
        background: linear-gradient(to right, #6a0dad, #8a2be2);
        color: white;
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        font-family: Arial, sans-serif;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }}
    </style>
    <div class="header">
        <h1>{title}</h1>
    </div>
    """, unsafe_allow_html=True)

def login_page():
    with st.container():
        page_header("🔑 Authentication Required")
        col1, col2, col3 = st.columns([1,3,1])
        with col2:
            with st.form("login_form"):
                st.markdown("### Please authenticate to continue")
                st.info(f"Admin Password: {ADMIN_PASSWORD}")  # Show password on login page
                master = st.text_input("Enter master password:", type="password")
                login_button = st.form_submit_button("Login")
                
                if login_button:
                    if master == ADMIN_PASSWORD:
                        st.session_state.authenticated = True
                        st.session_state.failed_attempts = 0
                        st.success("✅ Authentication successful!")
                        st.rerun()
                    else:
                        st.error("❌ Incorrect password!")

# 🌐 Main App UI
def main_app():
    # Sidebar
    with st.sidebar:
        st.markdown("""
        <style>
        .sidebar .sidebar-content {
            background: linear-gradient(to bottom, #6a0dad, #8a2be2);
            color: white;
        }
        </style>
        """, unsafe_allow_html=True)
        
        st.markdown("## Navigation")
        
        if st.button("🏠 Home"):
            st.session_state.page = "home"
        if st.button("💾 Store Data"):
            st.session_state.page = "store"
        if st.button("🔍 Retrieve Data"):
            st.session_state.page = "retrieve"
        if st.button("🔑 Re-authenticate"):
            st.session_state.authenticated = False
            st.rerun()
    
    # Page content
    if "page" not in st.session_state:
        st.session_state.page = "home"
    
    stored_data = load_data()
    
    # Home Page
    if st.session_state.page == "home":
        page_header("🔐 Secure Data System")
        st.markdown("""
        ### Welcome to the Secure Data System!
        
        This application allows you to:
        - 🔒 Encrypt sensitive data with military-grade encryption
        - 💾 Store your encrypted data securely
        - 🔍 Retrieve your data when needed
        
        **How to use:**
        1. Navigate to "Store Data" to encrypt and save your information
        2. Use "Retrieve Data" to decrypt your information when needed
        3. Always remember your secret key - without it, data cannot be recovered
        
        *Your security is our priority.*
        """)
        
    # Store Data Page
    elif st.session_state.page == "store":
        page_header("💾 Store Encrypted Data")
        with st.form("store_form"):
            user_text = st.text_area("Enter your sensitive text:")
            passkey = st.text_input("Create a strong secret key:", type="password")
            submit_button = st.form_submit_button("Encrypt & Save")
            
            if submit_button:
                if user_text and passkey:
                    encrypted = encrypt_data(user_text, passkey)
                    stored_data[encrypted] = "stored"
                    save_data(stored_data)
                    st.success("✅ Data encrypted and saved successfully!")
                    st.markdown("### Your Encrypted Data:")
                    st.code(encrypted, language="text")
                    st.warning("⚠️ Please copy and save this encrypted text along with your secret key. Without both, you cannot recover your data.")
                else:
                    st.error("Please enter both text and a secret key!")
    
    # Retrieve Data Page
    elif st.session_state.page == "retrieve":
        page_header("🔍 Retrieve Your Data")
        
        if st.session_state.failed_attempts >= 3:
            st.error("🚫 Too many failed attempts! Please re-authenticate from the sidebar.")
        else:
            with st.form("retrieve_form"):
                encrypted_input = st.text_area("Paste your encrypted text here:")
                passkey_input = st.text_input("Enter your secret key:", type="password")
                submit_button = st.form_submit_button("Decrypt")
                
                if submit_button:
                    if encrypted_input and passkey_input:
                        result = decrypt_data(encrypted_input, passkey_input)
                        if result:
                            st.success("✅ Decryption successful!")
                            st.markdown("### Your Decrypted Data:")
                            st.code(result, language="text")
                            st.session_state.failed_attempts = 0
                        else:
                            remaining = 3 - st.session_state.failed_attempts
                            st.error(f"❌ Incorrect key! {remaining} attempts remaining.")
                    else:
                        st.error("Please provide both encrypted text and secret key!")

# 🌐 App Flow
if not st.session_state.authenticated:
    login_page()
else:
    main_app()
    purple_footer()