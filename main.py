import streamlit as st
from app.ui import (
    page_strength_checker,
    page_hash_generator,
    page_dictionary,
    page_brute_force,
    page_hybrid,
    page_online,
)

st.set_page_config(page_title="Password Security Lab", page_icon="🔐", layout="wide")
st.title("🔐 Password Security Lab")
st.caption("CSCI369 Ethical Hacking — Password Cracking Demo")

PAGES = {
    "🔍 Strength Analyzer":   page_strength_checker,
    "⚙️  Hash Generator":      page_hash_generator,
    "📖 Dictionary Attack":    page_dictionary,
    "💪 Brute Force Attack":   page_brute_force,
    "🔀 Hybrid Attack":        page_hybrid,
    "🌐 Online Attack":        page_online,
}

page = st.sidebar.radio("Navigate", list(PAGES.keys()))
PAGES[page]()
