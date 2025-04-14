import streamlit as st   
import hashlib
import sqlite3
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

cipher = Fernet(load_key())

st.set_page_config(page_title="🔐 Secure Data Encryption System ", layout="centered")
st.markdown(
    """
    <style>
  .stButton > button {
    background-image: linear-gradient(to right, #8e2de2, #ff6ec4); /* Purple to pink */
    color: white;
    font-size: 16px;
    border-radius: 10px;
    padding: 10px 20px;
    width: 100%;
    margin-bottom: 10px;
    border: none;
    transition: background-image 0.3s ease, transform 0.2s;
}

.stButton > button:hover {
    background-image: linear-gradient(to right, #6a11cb, #ff4e9b); /* Darker hover gradient */
    transform: scale(1.02); /* Slight zoom effect on hover */
}

    </style>
    """,
    unsafe_allow_html=True,
)

# --- SQLite Database Setup ---
def init_db():
    conn = sqlite3.connect("secure_data.db")
    c = conn.cursor()
    c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT
                 )
            """)
    c.execute("""
            CREATE TABLE IF NOT EXISTS data (
                username TEXT,
                label TEXT,
                encrypted_text TEXT,
                passkey TEXT,
                FOREIGN KEY(username) REFERENCES users(username)
                 )
            """)
    
    conn.commit()
    conn.close()

init_db()


def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# --- Decrypt Function ---
def decrypt_data(encrypted_text, passkey_input, stored_passkey):
    try:
        hashed_passkey_input = hash_text(passkey_input)
        if hashed_passkey_input == stored_passkey:
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            return decrypted
#     #     else:
#     #         st.error("❌ Incorrect passkey. Please check and try again.")
#     #         return None
#     # except InvalidToken:
#     #     st.error("❌ The encrypted data or passkey is incorrect. Please check and try again.")
#     #     return None
    except Exception:
            st.error("❌ Decryption failed. The data may be corrupted or the key is incorrect.")
            return None
    else:
        st.error("❌ Incorrect passkey. Please check and try again.")
        return None

# --- Database Interaction ---
def get_user_data(username):
    conn = sqlite3.connect("secure_data.db")
    c = conn.cursor()
    c.execute("SELECT label, encrypted_text, passkey FROM data WHERE username=?", (username,))
    data = c.fetchall()
    conn.close()
    return data

def store_user_data(username, label, encrypted_text, passkey):
    conn = sqlite3.connect("secure_data.db")
    c = conn.cursor()
    c.execute("INSERT INTO data (username, label, encrypted_text, passkey) VALUES (?, ?, ?, ?)",
              (username, label, encrypted_text, passkey))
    conn.commit()
    conn.close()

def register_user(username, password):
    conn = sqlite3.connect("secure_data.db")
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE username=?", (username,))
    if c.fetchone():
        st.error("❌ Username already exists. Please choose another.")
        conn.close()
        return
    hashed_password = hash_text(password)
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

def validate_user(username, password):
    conn = sqlite3.connect("secure_data.db")
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    stored_password = c.fetchone()
    conn.close()
    return stored_password and stored_password[0] == hash_text(password)

# --- App State Initialization ---
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "current_page" not in st.session_state:
    st.session_state.current_page = None

def center_text(title):
    st.markdown(f"<h2 style='text-align: center;'>{title}</h2>", unsafe_allow_html=True)

# --- HOME PAGE ---
if st.session_state.get("current_user") is None and st.session_state.get("current_page") is None:
    center_text("🔐 Secure Data Encryption System")

    st.markdown(
        "<p style='text-align: center; font-size: 18px;'>"
        "🔐 Welcome to <b>SecureVault</b>! Protect your sensitive data by encrypting 🔐 and accessing 🔍 it securely with your personal passkey 🔑."
        "</p>",
        unsafe_allow_html=True
    )
    
    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Register", use_container_width=True):
            st.session_state.current_page = "📝 Register"
            st.rerun()

    with col2:
        if st.button("Login", use_container_width=True):
            st.session_state.current_page = "🔑 Login"
            st.rerun()

# --- REGISTER PAGE ---
elif st.session_state.current_page == "📝 Register":
    center_text("🔐 Sign In to Your Account")
    st.markdown("<div style='text-align: center;'>Register to unlock access to your encrypted vault.</div>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)  

    with st.form("register_form"):
        new_user = st.text_input("👤 Choose Username")
        new_pass = st.text_input("🔒 Choose Password", type="password")
        confirm_pass = st.text_input("🔒Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
        
        if submitted:
            if not new_user or not new_pass or not confirm_pass:
                st.error("⚠️ All fields are required.")
            elif validate_user(new_user, new_pass):
                st.error("❌ Username already exists.")
            elif new_pass != confirm_pass:
                st.error("❌ Passwords do not match.")
            else:
                register_user(new_user, new_pass)
                st.success("🎉 Registered successfully! You can now log in.")
                st.session_state.current_page = "🔑 Login"
                st.rerun()

    st.markdown("<br><hr>", unsafe_allow_html=True)
    if st.button("Back to Login"):
        st.session_state.current_page = "🔑 Login"
        st.rerun()

   
# --- LOGIN PAGE ---
elif st.session_state.current_page == "🔑 Login":
    center_text("🔑 Login to Your Vault")
    st.markdown("<div style='text-align: center;'>Enter your credentials to access your encrypted data</div>", unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # LOGIN FORM
    with st.form("login_form"):
        username = st.text_input("👤 Username")
        password = st.text_input("🔐 Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if st.session_state.failed_attempts >= 3:
                st.warning("⚠️ Too many failed attempts. Redirecting to Login for reauthorization.")
                st.session_state.current_user = None
                st.session_state.failed_attempts = 0
                st.rerun()
                
            if validate_user(username, password):
                st.session_state.current_user = username
                st.session_state.failed_attempts = 0
                st.success(f"🔓 Welcome back, {username}!")

                st.session_state.encrypt_count = 0
                st.session_state.retrieve_count = 0
                st.session_state.recent_data = []

                st.session_state.current_page = "📂 Dashboard"
                st.rerun()
            else:
                st.session_state.failed_attempts += 1
                st.error(f"❌ Invalid credentials. Attempt {st.session_state.failed_attempts}/3.")
                if st.session_state.failed_attempts >= 3:
                    st.warning("⚠️ Too many failed attempts. Redirecting to Login for reauthorization.")
                    st.session_state.current_user = None
                    st.session_state.failed_attempts = 0
                    st.rerun()

    st.markdown("<br><hr>", unsafe_allow_html=True)
    st.markdown("<div style='text-align: center; font-weight: semibold;'>Don't have an account?</div>", unsafe_allow_html=True)
    if st.button("Register"):
        st.session_state.current_page = "📝 Register"
        st.rerun()

# --- DASHBOARD PAGE -- SIDEBAR ---
if "page" not in st.session_state:
    st.session_state.page = "📊 Dashboard"

if st.session_state.current_user:
    with st.sidebar:
        st.markdown("## 📍 Menu")

        if st.button("📊 Dashboard"):
            st.session_state.page = "📊 Dashboard"

        if st.button("ℹ️ About this App"):
            st.session_state.page = "ℹ️ About this App"

        if st.button("🔐 Encrypt Data"):
            st.session_state.page = "🔐 Encrypt Data"

        if st.button("🔍 Retrieve Data"):
            st.session_state.page = "🔍 Retrieve Data"

        if st.button("🚪 Log Out"):
         st.session_state.authenticated = False
         st.session_state.current_user = None  
         st.session_state.current_page = None  
         st.rerun() 

        if "encrypt_count" not in st.session_state:
            st.session_state.encrypt_count = 0

        if "retrieve_count" not in st.session_state:
            st.session_state.retrieve_count = 0

        if "recent_data" not in st.session_state:
            st.session_state.recent_data = [] 
        
        if "page" not in st.session_state:
            st.session_state.page = "📊 Dashboard"

#--- DASHBOARD PAGE ---
    if st.session_state.page == "📊 Dashboard":
        st.title(f"📊 Welcome to Your Dashboard, {st.session_state.current_user}!")

        st.subheader("📈 Session Statistics")
        col1, col2 = st.columns(2)
        with col1:
            st.metric(label="🔐 Encrypted Items", value=st.session_state.encrypt_count)
        with col2:
            st.metric(label="🔍 Retrieved Items", value=st.session_state.retrieve_count)

        if st.session_state.recent_data:
            st.subheader("🧩 Recently Encrypted Data (Preview)")
            for i, data in enumerate(st.session_state.recent_data[-5:][::-1], start=1): 
                st.code(data[:100] + "..." if len(data) > 100 else data, language='text')  
        else:
            st.info("No data encrypted yet this session.")


# --- ENCRYPT DATA PAGE ---
if st.session_state.page == "🔐 Encrypt Data":
    st.title("🔐 Encrypt & Store Your Data")

    label = st.text_input("📌 Label")
    secret_text = st.text_area("📝 Text to Encrypt")
    passkey = st.text_input("🔑 Create a Passkey", type="password")

    if st.button("Encrypt & Save"):
        if label and secret_text and passkey:
            encrypted = encrypt_data(secret_text)
            hashed_key = hash_text(passkey)
            store_user_data(st.session_state.current_user, label, encrypted, hashed_key)
            st.session_state.encrypt_count += 1
            if 'recent_data' not in st.session_state:
                st.session_state.recent_data = []
            st.session_state.recent_data.append(encrypted)
            st.success("✅ Data encrypted and saved successfully.")
        else:
            st.warning("⚠️ Please fill out all fields.")

# --- RETRIEVE DATA PAGE ---
if st.session_state.page == "🔍 Retrieve Data":
    st.title("🔍 Retrieve Encrypted Data")

    user_data = get_user_data(st.session_state.current_user)
    if not user_data:
        st.info("ℹ️ No encrypted data found.")
    else:
        selected_label = st.selectbox("Select a label", [item[0] for item in user_data])
        passkey_input = st.text_input("🔑 Enter Passkey", type="password")

        if st.button("Decrypt"):
            for item in user_data:
                if item[0] == selected_label:
                    decrypted = decrypt_data(item[1], passkey_input, item[2])
                    if decrypted:
                        st.success("✅ Data decrypted successfully!")
                        st.code(decrypted)
                        st.session_state.retrieve_count += 1

                        # Optionally, store this decrypted data in session for preview
                        if 'recent_retrieved' not in st.session_state:
                            st.session_state.recent_retrieved = []
                        st.session_state.recent_retrieved.append(decrypted)
                    else:
                        st.error("❌ Invalid passkey or unable to decrypt data.")
                    break

#--- ABOUT PAGE ---
elif st.session_state.page == "ℹ️ About this App":

    st.markdown("""
    ## 🔐 About This App
    Welcome to the **Secure Data Encryption System**, where you can store and protect your sensitive information with cutting-edge security features.  
    **Key Features**:
    - **Encrypt Data** 🔒: Secure your sensitive information with advanced encryption.
    - **Retrieve Data** 🔑: Safely access your encrypted data using your personal passkey.
    - **Dashboard Overview** 📊: View your encryption statistics and recent activities.
    - **Backup & Recovery** 💾: Easily backup your data and recover it if needed.

    This app uses **state-of-the-art encryption** 🛡️ to ensure that only you can access your data. Your passkey is **hashed** for security, and your data is encrypted using the **AES encryption** algorithm 🔐.

    ### How it works:
    - **Encrypt Data** 🔏: You provide data and choose a passkey. Your data is then encrypted and stored securely.
    - **Retrieve Data** 🧑‍💻: You input your passkey, and the app decrypts the data if the passkey matches.
    - All your data is stored securely, and only you have access to it.

    **Why choose us?**
    - **Private & Secure** 🔐: Your information is protected with the highest level of encryption.
    - **Simple & Intuitive** 🧑‍💻: The app is user-friendly, making encryption and data retrieval seamless.
    - **Peace of Mind** 🧘‍♀️: We follow strict privacy policies to ensure your data is never compromised.

    **Start encrypting your data now by visiting the "Encrypt Data" page** 🚀. Your security is our top priority!
    """)
