import streamlit as st
import hashlib
import sqlite3

# Create a database connection
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create users table if it does not exist
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT
    )
''')
conn.commit()

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to verify passwords
def verify_password(stored_password, provided_password):
    return stored_password == hash_password(provided_password)

# Signup function
def signup():
    st.title("Signup")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Signup"):
        if password == confirm_password:
            hashed_password = hash_password(password)
            try:
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
                st.success("You have successfully created an account")
                st.info("Go to Login page to login")
            except sqlite3.IntegrityError:
                st.error("Username already exists")
        else:
            st.error("Passwords do not match")

# Login function
def login():
    st.title("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        if result and verify_password(result[0], password):
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            st.success("Login successful")
        else:
            st.error("Invalid username or password")

# Forgot password function
def forgot_password():
    st.title("Forgot Password")
    username = st.text_input("Username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm New Password", type="password")
    if st.button("Reset Password"):
        if new_password == confirm_password:
            hashed_password = hash_password(new_password)
            c.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()
            st.success("Password reset successful")
            st.info("Go to Login page to login")
        else:
            st.error("Passwords do not match")

# Logout function
def logout():
    st.session_state['logged_in'] = False
    st.session_state['username'] = None
    st.success("You have been logged out")

# Main function to handle routing
def main():
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False

    if st.session_state['logged_in']:
        st.sidebar.button("Logout", on_click=logout)
        st.title("Welcome to Moodtunes")
        st.write("You are logged in as ", st.session_state['username'])
        # Include the music.py content here
        from music import music_page
        music_page()

    else:
        page = st.sidebar.selectbox("Choose a page", ["Login", "Signup", "Forgot Password"])
        if page == "Login":
            login()
        elif page == "Signup":
            signup()
        elif page == "Forgot Password":
            forgot_password()

if __name__ == "__main__":
    main()