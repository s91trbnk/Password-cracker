import math
import re


def calculate_entropy(password: str) -> float:
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32
    if charset == 0:
        return 0.0
    return len(password) * math.log2(charset)


def check_strength(password: str) -> dict:
    entropy = calculate_entropy(password)
    length = len(password)

    issues = []
    if length < 8:
        issues.append("Too short (minimum 8 characters)")
    if not re.search(r"[A-Z]", password):
        issues.append("No uppercase letters")
    if not re.search(r"[0-9]", password):
        issues.append("No digits")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("No special characters")

    if entropy < 28:
        score, label = 0, "Very Weak"
    elif entropy < 36:
        score, label = 1, "Weak"
    elif entropy < 60:
        score, label = 2, "Moderate"
    elif entropy < 128:
        score, label = 3, "Strong"
    else:
        score, label = 4, "Very Strong"

    return {
        "password": password,
        "length": length,
        "entropy": round(entropy, 2),
        "score": score,
        "label": label,
        "issues": issues,
    }
