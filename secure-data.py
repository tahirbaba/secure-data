import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# 🔐 Key for encryption (keep this secure in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# 🔸 Initialize session states
if "users" not in st.session_state:
    st.session_state.users = {}  # username: hashed_password
if "data" not in st.session_state:
    st.session_state.data = {}  # username: [{"encrypted":..., "passkey":...}]
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = ""
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# 🔐 Hash password
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

# 🔒 Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# 🔓 Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_pass = hash_text(passkey)
    user_data = st.session_state.data.get(st.session_state.current_user, [])

    for entry in user_data:
        if entry["encrypted"] == encrypted_text and entry["passkey"] == hashed_pass:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# 🧭 Navigation
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigate", menu)

# 🏠 Home
if choice == "Home":
    st.title("🛡️ Secure Data Encryption System")
    st.markdown("""
### 🔐 Welcome to Secure Data Encryption System

Protect your sensitive data with military-grade encryption — simple, fast, and safe.

---

✅ **Register & Login** to access your personal vault.  
🔒 **Encrypt your data** using a secret passkey only you know.  
📦 **Store encrypted data** safely in your private account.  
🔓 **Retrieve and decrypt** anytime with your secure passkey.  
🚫 **3 wrong attempts?** You’re automatically logged out for protection.

---

🔐 Your privacy is our priority — start securing your data now.
""")

# 📝 Registration
elif choice == "Register":
    st.subheader("📝 Register New User")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")

    if st.button("Register"):
        if new_user in st.session_state.users:
            st.warning("⚠️ User already exists.")
        elif new_user and new_pass:
            st.session_state.users[new_user] = hash_text(new_pass)
            st.success("✅ Registered successfully! Please login.")
        else:
            st.error("❌ Fill both fields.")

# 🔐 Login
elif choice == "Login":
    st.subheader("🔐 Login")
    user = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if user in st.session_state.users and st.session_state.users[user] == hash_text(password):
            st.session_state.logged_in = True
            st.session_state.current_user = user
            st.session_state.failed_attempts = 0
            st.success(f"✅ Logged in as: {user}")
        else:
            st.error("❌ Invalid credentials.")

# 📂 Store Data
elif choice == "Store Data":
    if st.session_state.logged_in:
        st.subheader("📂 Store Data")
        text = st.text_area("Enter your data:")
        passkey = st.text_input("Create a passkey:", type="password")

        if st.button("Encrypt & Store"):
            if text and passkey:
                encrypted = encrypt_data(text)
                hashed_passkey = hash_text(passkey)
                st.session_state.data.setdefault(st.session_state.current_user, []).append({
                    "encrypted": encrypted,
                    "passkey": hashed_passkey
                })
                st.success("✅ Data encrypted & stored.")
                st.code(encrypted, language="text")
            else:
                st.error("❌ Fill all fields.")
    else:
        st.warning("🔒 Please login to store data.")

# 🔍 Retrieve Data
elif choice == "Retrieve Data":
    if st.session_state.logged_in:
        st.subheader("🔍 Retrieve Data")
        encrypted_input = st.text_area("Paste Encrypted Text:")
        passkey_input = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_input and passkey_input:
                result = decrypt_data(encrypted_input, passkey_input)
                if result:
                    st.success("✅ Data decrypted:")
                    st.code(result)
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Wrong passkey! Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔒 Too many failed attempts. Logged out.")
                        st.session_state.logged_in = False
                        st.session_state.current_user = ""
            else:
                st.error("❌ Fill all fields.")
    else:
        st.warning("🔒 Please login to retrieve data.")

# 🚪 Logout
elif choice == "Logout":
    st.subheader("🚪 Logout")
    if st.session_state.logged_in:
        st.session_state.logged_in = False
        st.session_state.current_user = ""
        st.success("✅ You have been logged out.")
    else:
        st.info("ℹ️ You are not logged in.")
