import hashlib
from pathlib import Path
from passlib.hash import sha512_crypt


SUPPORTED_ALGORITHMS = ["md5", "sha1", "sha256", "ntlm", "sha512crypt"]


def hash_password(password: str, algorithm: str) -> str:
    algorithm = algorithm.lower()

    if algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "ntlm":
        # NTLM is MD4 of the UTF-16LE encoded password
        return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
    elif algorithm == "sha512crypt":
        # Linux /etc/shadow format ($6$...) — used in passlib instead of removed crypt module
        return sha512_crypt.hash(password)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def generate_hash_file(passwords: list[str], algorithm: str, output_path: str) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        for pw in passwords:
            h = hash_password(pw, algorithm)
            f.write(f"{h}\n")
    return str(out)


def load_hash_file(path: str) -> list[str]:
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]
