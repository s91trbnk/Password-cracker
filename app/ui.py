import streamlit as st
from pathlib import Path
from app.strength import check_strength
from app.hashing import hash_password, generate_hash_file, SUPPORTED_ALGORITHMS
from app.cracker import (
    crack_dictionary, crack_brute_force, crack_hybrid, crack_online,
    HASHCAT_MODES, CHARSET_TOKENS, ONLINE_SERVICES, available_rules,
)
import plotly.graph_objects as go
import plotly.express as px
import tempfile
import os


# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT  = Path(__file__).parent.parent
HASHES_DIR    = PROJECT_ROOT / "hashes"
WORDLISTS_DIR = PROJECT_ROOT / "wordlists"
HASHES_DIR.mkdir(exist_ok=True)
WORDLISTS_DIR.mkdir(exist_ok=True)


# ── Shared helpers ────────────────────────────────────────────────────────────

def _get_hash_files():
    return list(HASHES_DIR.glob("*.txt")) + list(HASHES_DIR.glob("*.hash"))

def _get_wordlists():
    return list(WORDLISTS_DIR.glob("*.txt"))


def _resolve_hash_file(key_prefix: str) -> str | None:
    """
    Shared widget that lets the user provide a hash file three ways:
      1. Paste hashes directly
      2. Upload a file
      3. Select an existing file from hashes/
    Returns the path to the hash file to use, or None if nothing provided.
    """
    mode = st.radio(
        "Hash input",
        ["Paste hashes", "Upload a file", "Select existing file"],
        horizontal=True,
        key=f"{key_prefix}_mode",
    )

    if mode == "Paste hashes":
        pasted = st.text_area(
            "Paste hashes here (one per line)",
            placeholder="5f4dcc3b5aa765d61d8327deb882cf99\nabc123...",
            key=f"{key_prefix}_paste",
            height=150,
        )
        if pasted.strip():
            # Save to a temp file inside hashes/ so hashcat can read it
            tmp_path = HASHES_DIR / f"_pasted_{key_prefix}.txt"
            tmp_path.write_text(pasted.strip())
            st.caption(f"Saved {len(pasted.strip().splitlines())} hash(es) to temp file.")
            return str(tmp_path)
        return None

    elif mode == "Upload a file":
        uploaded = st.file_uploader(
            "Upload hash file (.txt or .hash)",
            type=["txt", "hash"],
            key=f"{key_prefix}_upload",
        )
        if uploaded:
            save_path = HASHES_DIR / uploaded.name
            save_path.write_bytes(uploaded.read())
            st.caption(f"Saved to `{save_path}`")
            return str(save_path)
        return None

    else:  # Select existing
        files = _get_hash_files()
        if not files:
            st.warning(f"No hash files in `{HASHES_DIR}`. Paste hashes or upload a file instead.")
            return None
        selected = st.selectbox("Select hash file", files, key=f"{key_prefix}_select")
        return str(selected)


def _show_results(result: dict):
    """Shared results display used by all offline attack pages."""
    if "error" in result:
        st.error(result["error"])
        return

    col1, col2 = st.columns(2)
    col1.metric("Passwords Cracked", result["total_cracked"])
    col2.metric("Time Taken", f"{result['elapsed_seconds']}s")

    if result["cracked"]:
        st.success(f"✅ {result['total_cracked']} password(s) cracked!")
        st.subheader("Cracked Passwords")
        st.table(result["cracked"])

        labels = [r["plaintext"] for r in result["cracked"]]
        fig = px.bar(
            x=labels, y=[1] * len(labels),
            labels={"x": "Password", "y": ""},
            title=f"{result['attack_type']} Attack — Cracked Passwords",
            color=labels,
        )
        fig.update_layout(showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No passwords cracked. Try a larger wordlist or different settings.")

    if result.get("stderr"):
        with st.expander("Tool output (debug)"):
            st.code(result["stderr"])


# ── Page 1: Strength Analyzer ─────────────────────────────────────────────────

def page_strength_checker():
    st.header("🔍 Password Strength Analyzer")
    st.write("Analyze a password's entropy and complexity.")
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
                    {"range": [0,  28], "color": "#ffcdd2"},
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


# ── Page 2: Hash Generator ────────────────────────────────────────────────────

def page_hash_generator():
    st.header("⚙️ Hash Generator")
    st.write(
        "Convert plaintext passwords into hashes — simulates what a stolen password "
        "database looks like. Use the output to test the attack modules."
    )

    passwords_input = st.text_area("Enter passwords (one per line)", height=150)
    algorithm = st.selectbox("Hash Algorithm", SUPPORTED_ALGORITHMS)
    filename  = st.text_input("Output filename", value="target.txt")

    if st.button("Generate Hash File"):
        passwords = [p.strip() for p in passwords_input.splitlines() if p.strip()]
        if not passwords:
            st.error("Enter at least one password.")
            return
        out_path = HASHES_DIR / filename
        generate_hash_file(passwords, algorithm, str(out_path))
        st.success(f"Hash file saved to: `{out_path}` — now select it in any attack page.")
        rows = [{"plaintext": p, "hash": hash_password(p, algorithm)} for p in passwords]
        st.table(rows)


# ── Page 3: Dictionary Attack ─────────────────────────────────────────────────

def page_dictionary():
    st.header("📖 Dictionary Attack")
    st.info(
        "**How it works:** Tries every word in a wordlist directly against the hashes. "
        "Fast and effective against common passwords. Best with **rockyou.txt** (14M passwords)."
    )

    hash_file = _resolve_hash_file("dict")
    if not hash_file:
        return

    wordlists = _get_wordlists()
    if not wordlists:
        st.warning(f"No wordlists found in `{WORDLISTS_DIR}`. Add rockyou.txt or common.txt.")
        return

    wordlist  = st.selectbox("Wordlist", wordlists)
    algorithm = st.selectbox("Hash Algorithm", list(HASHCAT_MODES.keys()))

    rules = available_rules()
    use_rules = st.checkbox("Apply hashcat rules (stronger mutations)")
    rules_file = None
    if use_rules:
        if rules:
            rules_file = st.selectbox("Rule file", rules)
        else:
            st.warning("No rule files found at /usr/share/hashcat/rules/. Rules disabled.")

    if st.button("▶ Start Dictionary Attack"):
        with st.spinner("Running dictionary attack..."):
            result = crack_dictionary(str(hash_file), str(wordlist), algorithm, rules_file)
        _show_results(result)


# ── Page 4: Brute Force Attack ────────────────────────────────────────────────

def page_brute_force():
    st.header("💪 Brute Force Attack")
    st.info(
        "**How it works:** Tries every possible character combination up to a given length. "
        "Guaranteed to crack any password — but gets exponentially slower with length. "
        "Best for short passwords (≤6 chars)."
    )

    hash_file = _resolve_hash_file("bf")
    if not hash_file:
        return

    algorithm = st.selectbox("Hash Algorithm", list(HASHCAT_MODES.keys()))

    st.subheader("Character Set")
    charset_options = list(CHARSET_TOKENS.keys())
    selected = []
    cols = st.columns(len(charset_options))
    for i, opt in enumerate(charset_options):
        if cols[i].checkbox(opt, value=(i == 0)):
            selected.append(opt)

    max_len = st.slider("Maximum password length", min_value=1, max_value=8, value=6)

    if selected:
        charset_size = sum([
            26 if "Lowercase" in c else
            26 if "Uppercase" in c else
            10 if "Digits"    in c else
            32 for c in selected
        ])
        total_combos = sum(charset_size ** i for i in range(1, max_len + 1))
        st.caption(f"⚠️ Estimated combinations: **{total_combos:,}**")

    if st.button("▶ Start Brute Force Attack"):
        if not selected:
            st.error("Select at least one character set.")
            return
        with st.spinner(f"Running brute force (up to {max_len} chars)..."):
            result = crack_brute_force(str(hash_file), algorithm, selected, max_len)
        _show_results(result)


# ── Page 5: Hybrid Attack ─────────────────────────────────────────────────────

def page_hybrid():
    st.header("🔀 Hybrid Attack")
    st.info(
        "**How it works:** Combines a wordlist with mutations.\n"
        "- **Mask mode** — appends characters to each word (e.g. `password` → `password123`)\n"
        "- **Rules mode** — applies transformations like l33tspeak, capitalization, reversal"
    )

    hash_file = _resolve_hash_file("hybrid")
    if not hash_file:
        return

    wordlists = _get_wordlists()
    if not wordlists:
        st.warning(f"No wordlists found in `{WORDLISTS_DIR}`. Add rockyou.txt or common.txt.")
        return

    wordlist  = st.selectbox("Wordlist", wordlists)
    algorithm = st.selectbox("Hash Algorithm", list(HASHCAT_MODES.keys()))

    mode = st.radio("Hybrid mode", ["Mask (append characters)", "Rules (transformations)"])

    append_mask = "?d?d?d"
    rules_file  = None

    if mode == "Mask (append characters)":
        st.markdown("**Tokens:** `?l`=lowercase · `?u`=uppercase · `?d`=digit · `?s`=special")
        append_mask = st.text_input("Mask to append", value="?d?d?d",
                                    help="e.g. ?d?d?d → tries word000 to word999")
    else:
        rules = available_rules()
        if rules:
            rules_file = st.selectbox("Rule file", rules)
            st.caption("Applies transformations: `password` → `P@ssw0rd`, `p4ssword`, etc.")
        else:
            st.warning("No rule files found at /usr/share/hashcat/rules/. Switch to Mask mode.")
            return

    if st.button("▶ Start Hybrid Attack"):
        with st.spinner("Running hybrid attack..."):
            result = crack_hybrid(str(hash_file), str(wordlist), algorithm, append_mask, rules_file)
        _show_results(result)


# ── Page 6: Online Attack ─────────────────────────────────────────────────────

def page_online():
    st.header("🌐 Online Attack (Hydra)")
    st.info(
        "**How it works:** Attacks a **live service** (SSH, FTP, etc.) on the target VM directly — "
        "no hash file needed. Target should be your **Metasploitable VM** in the isolated lab."
    )
    st.warning("⚠️ Only use this against your own lab VMs. Never against public or production systems.")

    col1, col2 = st.columns(2)
    target_ip = col1.text_input("Target IP", placeholder="e.g. 192.168.100.x")
    service   = col2.selectbox("Service", ONLINE_SERVICES)

    port = st.number_input("Port (0 = default)", min_value=0, max_value=65535, value=0)
    port = int(port) if port > 0 else None

    wordlists = _get_wordlists()
    if not wordlists:
        st.warning(f"No wordlists found in `{WORDLISTS_DIR}`. Add rockyou.txt or common.txt.")
        return
    wordlist = st.selectbox("Wordlist", wordlists)

    auth_mode = st.radio("Authentication", ["Single username", "Username list file"])
    username  = None
    userlist  = None

    if auth_mode == "Single username":
        username = st.text_input("Username", placeholder="e.g. msfadmin")
    else:
        userlist_files = list(WORDLISTS_DIR.glob("*.txt"))
        if userlist_files:
            userlist = str(st.selectbox("Username list file", userlist_files))
        else:
            st.warning("No username list files found in wordlists/.")
            return

    threads = st.slider("Parallel threads", min_value=1, max_value=16, value=4)

    if st.button("▶ Start Online Attack"):
        if not target_ip:
            st.error("Enter the target IP address.")
            return
        with st.spinner(f"Running Hydra against {service}://{target_ip} ..."):
            result = crack_online(target_ip, service, str(wordlist), username, userlist, port, threads)

        if "error" in result:
            st.error(result["error"])
            return

        col1, col2, col3 = st.columns(3)
        col1.metric("Target", result["target"])
        col2.metric("Credentials Found", result["total_cracked"])
        col3.metric("Time", f"{result['elapsed_seconds']}s")

        if result["cracked"]:
            st.success("✅ Credentials found!")
            st.table(result["cracked"])
        else:
            st.warning("No credentials found. Try a different wordlist or username.")

        with st.expander("Full Hydra output"):
            st.code(result.get("stdout", ""))
