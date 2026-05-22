import streamlit as st
from app.ui import page_strength_checker, page_hash_generator, page_cracker

st.set_page_config(page_title="Password Security Lab", page_icon="🔐", layout="wide")
st.title("Password Security Lab")

page = st.sidebar.radio("Navigate", ["Strength Analyzer", "Hash Generator", "Dictionary Attack"])

if page == "Strength Analyzer":
    page_strength_checker()
elif page == "Hash Generator":
    page_hash_generator()
elif page == "Dictionary Attack":
    page_cracker()
