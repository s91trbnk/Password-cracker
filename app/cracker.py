import subprocess
import shutil
import time
from pathlib import Path


# ── Constants ────────────────────────────────────────────────────────────────

HASHCAT_MODES = {
    "md5":        0,
    "sha1":       100,
    "sha256":     1400,
    "ntlm":       1000,
    "sha512crypt": 1800,
}

# hashcat charset tokens
CHARSET_TOKENS = {
    "Lowercase (a-z)": "?l",
    "Uppercase (A-Z)": "?u",
    "Digits (0-9)":    "?d",
    "Special (!@#...)": "?s",
}

ONLINE_SERVICES = ["ssh", "ftp", "telnet", "smb", "http-get", "rdp"]

HASHCAT_RULES_DIR = Path("/usr/share/hashcat/rules")
COMMON_RULES = ["best64.rule", "d3ad0ne.rule", "rockyou-30000.rule", "dive.rule"]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _available(tool: str) -> bool:
    return shutil.which(tool) is not None


def _parse_potfile(pot_path: str) -> list[dict]:
    results = []
    try:
        with open(pot_path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    hash_val, plaintext = line.split(":", 1)
                    results.append({"hash": hash_val, "plaintext": plaintext})
    except FileNotFoundError:
        pass
    return results


def _run_hashcat(cmd: list[str], pot_file: str) -> dict:
    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    elapsed = round(time.time() - start, 2)
    cracked = _parse_potfile(pot_file)
    return {
        "elapsed_seconds": elapsed,
        "cracked": cracked,
        "total_cracked": len(cracked),
        "returncode": proc.returncode,
        "stderr": proc.stderr,
    }


def _parse_hydra_output(output: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        if "login:" in line and "password:" in line:
            try:
                login = line.split("login:")[1].split("password:")[0].strip()
                password = line.split("password:")[1].strip()
                results.append({"username": login, "password": password})
            except (IndexError, ValueError):
                pass
    return results


# ── Attack 1: Dictionary ──────────────────────────────────────────────────────

def crack_dictionary(
    hash_file: str,
    wordlist: str,
    algorithm: str,
    rules_file: str | None = None,
) -> dict:
    """
    Offline dictionary attack.
    Tries every word in the wordlist directly against the hash file.
    Works great with rockyou.txt for weak/common passwords.
    """
    if not _available("hashcat"):
        return {"error": "hashcat not found — run: sudo apt install hashcat"}

    pot_file = str(Path(hash_file).with_suffix(".dict.pot"))
    cmd = [
        "hashcat", "-a", "0",
        "-m", str(HASHCAT_MODES[algorithm]),
        "--potfile-path", pot_file,
        "--quiet", "--force",
        hash_file, wordlist,
    ]
    if rules_file:
        cmd += ["-r", rules_file]

    result = _run_hashcat(cmd, pot_file)
    result.update({"attack_type": "Dictionary", "tool": "hashcat"})
    return result


# ── Attack 2: Brute Force ─────────────────────────────────────────────────────

def crack_brute_force(
    hash_file: str,
    algorithm: str,
    charsets: list[str],
    max_length: int,
) -> dict:
    """
    Offline brute force (mask) attack.
    Tries every possible combination of the selected character sets
    up to max_length characters. Uses hashcat --increment to try all
    lengths from 1 up to max_length automatically.

    Warning: exponentially slower as length and charset size increase.
    """
    if not _available("hashcat"):
        return {"error": "hashcat not found — run: sudo apt install hashcat"}
    if not charsets:
        return {"error": "Select at least one character set."}

    # Build mask: e.g. ?l?u?d for lowercase+uppercase+digits, repeated max_length times
    mask_unit = "".join(CHARSET_TOKENS[c] for c in charsets)
    mask = mask_unit * max_length

    pot_file = str(Path(hash_file).with_suffix(".bf.pot"))
    cmd = [
        "hashcat", "-a", "3",
        "-m", str(HASHCAT_MODES[algorithm]),
        "--potfile-path", pot_file,
        "--increment",
        "--increment-min", "1",
        "--increment-max", str(max_length),
        "--quiet", "--force",
        hash_file, mask,
    ]

    result = _run_hashcat(cmd, pot_file)
    result.update({"attack_type": "Brute Force", "tool": "hashcat", "mask": mask})
    return result


# ── Attack 3: Hybrid ──────────────────────────────────────────────────────────

def crack_hybrid(
    hash_file: str,
    wordlist: str,
    algorithm: str,
    append_mask: str,
    rules_file: str | None = None,
) -> dict:
    """
    Offline hybrid attack: wordlist + appended mask.
    Takes each word from the wordlist and appends character combinations.
    Example: 'password' + ?d?d?d → tries password000 through password999.
    Also supports rule-based mutations (e.g. l33tspeak, capitalization).
    """
    if not _available("hashcat"):
        return {"error": "hashcat not found — run: sudo apt install hashcat"}

    pot_file = str(Path(hash_file).with_suffix(".hybrid.pot"))

    if rules_file:
        # Rule-based hybrid: dictionary + rules (more powerful than mask)
        cmd = [
            "hashcat", "-a", "0",
            "-m", str(HASHCAT_MODES[algorithm]),
            "--potfile-path", pot_file,
            "--quiet", "--force",
            "-r", rules_file,
            hash_file, wordlist,
        ]
    else:
        # Mask-based hybrid: wordlist + appended mask
        cmd = [
            "hashcat", "-a", "6",
            "-m", str(HASHCAT_MODES[algorithm]),
            "--potfile-path", pot_file,
            "--quiet", "--force",
            hash_file, wordlist, append_mask,
        ]

    result = _run_hashcat(cmd, pot_file)
    result.update({
        "attack_type": "Hybrid",
        "tool": "hashcat",
        "append_mask": append_mask if not rules_file else "rule-based",
    })
    return result


# ── Attack 4: Online (Hydra) ──────────────────────────────────────────────────

def crack_online(
    target_ip: str,
    service: str,
    wordlist: str,
    username: str | None = None,
    userlist: str | None = None,
    port: int | None = None,
    threads: int = 4,
) -> dict:
    """
    Online attack using Hydra against a live network service.
    Target should be Metasploitable VM in your isolated lab.
    Supports: ssh, ftp, telnet, smb, http-get, rdp.

    Does NOT require a hash file — attacks the live service directly.
    """
    if not _available("hydra"):
        return {"error": "hydra not found — run: sudo apt install hydra"}
    if not target_ip.strip():
        return {"error": "Enter the target IP address."}
    if not username and not userlist:
        return {"error": "Provide a username or a username list file."}

    cmd = ["hydra", "-t", str(threads), "-P", wordlist]

    if username:
        cmd += ["-l", username]
    else:
        cmd += ["-L", userlist]

    if port:
        cmd += ["-s", str(port)]

    cmd.append(f"{service}://{target_ip}")

    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    elapsed = round(time.time() - start, 2)

    cracked = _parse_hydra_output(proc.stdout)

    return {
        "attack_type": "Online",
        "tool": "hydra",
        "target": f"{service}://{target_ip}",
        "elapsed_seconds": elapsed,
        "cracked": cracked,
        "total_cracked": len(cracked),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def available_rules() -> list[str]:
    """Return hashcat rule files available on this system."""
    found = []
    for rule in COMMON_RULES:
        p = HASHCAT_RULES_DIR / rule
        if p.exists():
            found.append(str(p))
    return found
