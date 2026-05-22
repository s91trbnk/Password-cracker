import streamlit as st
from pathlib import Path
from app.strength import check_strength
from app.hashing import hash_password, generate_hash_file, SUPPORTED_ALGORITHMS
from app.cracker import crack_with_hashcat, crack_with_john, HASHCAT_MODES, JOHN_FORMATS
import plotly.graph_objects as go


# Absolute paths based on project root — works regardless of where streamlit is called from
PROJECT_ROOT = Path(__file__).parent.parent
HASHES_DIR = PROJECT_ROOT / "hashes"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"

# Make sure directories exist
HASHES_DIR.mkdir(exist_ok=True)
WORDLISTS_DIR.mkdir(exist_ok=True)


def page_strength_checker():
    st.header("Password Strength Analyzer")
    password = st.text_input("Enter a password", type="password")

    if password:
        result = check_strength(password)

        col1, col2, col3 = st.columns(3)
        col1.metric("Entropy (bits)", result["entropy"])
        col2.metric("Length", result["length"])
        col3.metric("Strength", result["label"])

        colors = ["#d32f2f", "#f57c00", "#fbc02d", "#388e3c", "#1565c0"]
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=result["entropy"],
            title={"text": "Entropy (bits)"},
            gauge={
                "axis": {"range": [0, 128]},
                "bar": {"color": colors[result["score"]]},
                "steps": [
                    {"range": [0, 28], "color": "#ffcdd2"},
                    {"range": [28, 36], "color": "#ffe0b2"},
                    {"range": [36, 60], "color": "#fff9c4"},
                    {"range": [60, 128], "color": "#c8e6c9"},
                ],
            },
        ))
        st.plotly_chart(fig, use_container_width=True)

        if result["issues"]:
            st.warning("Issues found:")
            for issue in result["issues"]:
                st.write(f"- {issue}")
        else:
            st.success("No issues found.")


def page_hash_generator():
    st.header("Hash Generator")
    st.write("Generate a hash file to use as a cracking target in the lab.")

    passwords_input = st.text_area("Enter passwords (one per line)")
    algorithm = st.selectbox("Hash Algorithm", SUPPORTED_ALGORITHMS)
    filename = st.text_input("Output filename", value="target.txt")

    if st.button("Generate Hash File"):
        passwords = [p.strip() for p in passwords_input.splitlines() if p.strip()]
        if not passwords:
            st.error("Enter at least one password.")
            return
        out_path = HASHES_DIR / filename
        generate_hash_file(passwords, algorithm, str(out_path))
        st.success(f"Saved to {out_path}")
        st.code("\n".join([f"{hash_password(p, algorithm)}  ({p})" for p in passwords]))


def page_cracker():
    st.header("Dictionary Attack")

    hash_files = list(HASHES_DIR.glob("*.txt")) + list(HASHES_DIR.glob("*.hash"))
    wordlists = list(WORDLISTS_DIR.glob("*.txt"))

    if not hash_files:
        st.warning(f"No hash files found in {HASHES_DIR}. Generate one first.")
        return
    if not wordlists:
        st.warning(f"No wordlists found in {WORDLISTS_DIR}. Add rockyou.txt or use the bundled common.txt.")
        return

    hash_file = st.selectbox("Target hash file", hash_files)
    wordlist = st.selectbox("Wordlist", wordlists)
    algorithm = st.selectbox("Hash Algorithm", list(HASHCAT_MODES.keys()))
    tool = st.radio("Tool", ["hashcat", "john"])

    if st.button("Start Attack"):
        with st.spinner("Running attack..."):
            if tool == "hashcat":
                result = crack_with_hashcat(
                    str(hash_file), str(wordlist), HASHCAT_MODES[algorithm]
                )
            else:
                result = crack_with_john(
                    str(hash_file), str(wordlist), JOHN_FORMATS[algorithm]
                )

        if "error" in result:
            st.error(result["error"])
            return

        st.success(f"Done in {result['elapsed_seconds']}s — {result['total_cracked']} cracked")

        if result["cracked"]:
            st.subheader("Cracked Passwords")
            st.table(result["cracked"])

            labels = [r["plaintext"] for r in result["cracked"]]
            fig = go.Figure(go.Bar(x=labels, y=[1] * len(labels), text=labels))
            fig.update_layout(title="Cracked Passwords", xaxis_title="Password", yaxis_title="Count")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No passwords cracked with this wordlist.")
