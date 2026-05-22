import subprocess
import shutil
import time
from pathlib import Path


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def crack_with_hashcat(
    hash_file: str,
    wordlist: str,
    hash_mode: int,
    rules_file: str | None = None,
) -> dict:
    """
    Runs hashcat in dictionary attack mode (-a 0) and returns results.
    hash_mode: hashcat -m value (0=MD5, 100=SHA1, 1400=SHA256, 1000=NTLM, 1800=sha512crypt)
    """
    if not _tool_available("hashcat"):
        return {"error": "hashcat not found. Install it on Kali: sudo apt install hashcat"}

    pot_file = Path(hash_file).with_suffix(".pot")
    cmd = [
        "hashcat",
        "-m", str(hash_mode),
        "-a", "0",
        "--potfile-path", str(pot_file),
        "--quiet",
        hash_file,
        wordlist,
    ]
    if rules_file:
        cmd += ["-r", rules_file]

    start = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = round(time.time() - start, 2)

    cracked = _parse_potfile(str(pot_file))
    return {
        "tool": "hashcat",
        "elapsed_seconds": elapsed,
        "cracked": cracked,
        "total_cracked": len(cracked),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def crack_with_john(
    hash_file: str,
    wordlist: str,
    format_flag: str | None = None,
) -> dict:
    """
    Runs john the ripper in wordlist mode and returns results.
    format_flag: e.g. 'raw-md5', 'raw-sha1', 'nt', 'sha512crypt'
    """
    if not _tool_available("john"):
        return {"error": "john not found. Install it on Kali: sudo apt install john"}

    cmd = ["john", f"--wordlist={wordlist}", hash_file]
    if format_flag:
        cmd.append(f"--format={format_flag}")

    start = time.time()
    subprocess.run(cmd, capture_output=True, text=True)
    elapsed = round(time.time() - start, 2)

    show_cmd = ["john", "--show", hash_file]
    if format_flag:
        show_cmd.append(f"--format={format_flag}")
    show_result = subprocess.run(show_cmd, capture_output=True, text=True)

    cracked = _parse_john_show(show_result.stdout)
    return {
        "tool": "john",
        "elapsed_seconds": elapsed,
        "cracked": cracked,
        "total_cracked": len(cracked),
    }


def _parse_potfile(pot_path: str) -> list[dict]:
    results = []
    try:
        with open(pot_path, "r") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    hash_val, plaintext = line.split(":", 1)
                    results.append({"hash": hash_val, "plaintext": plaintext})
    except FileNotFoundError:
        pass
    return results


def _parse_john_show(output: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        # john --show outputs: hash:plaintext
        if ":" in line and not line.startswith("0 password"):
            parts = line.split(":")
            if len(parts) >= 2:
                results.append({"hash": parts[0], "plaintext": parts[1]})
    return results


HASHCAT_MODES = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "ntlm": 1000,
    "sha512crypt": 1800,
}

JOHN_FORMATS = {
    "md5": "raw-md5",
    "sha1": "raw-sha1",
    "sha256": "raw-sha256",
    "ntlm": "nt",
    "sha512crypt": "sha512crypt",
}
