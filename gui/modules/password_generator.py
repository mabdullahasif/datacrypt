"""
DataCrypt GUI — Cryptographic Password Generator
Uses Python's `secrets` module backed by OS CSPRNG (os.urandom).
"""

import secrets
import string


# Character pools
_UPPERCASE = string.ascii_uppercase
_LOWERCASE = string.ascii_lowercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?~"

# Limits
MIN_LENGTH = 16
DEFAULT_LENGTH = 32
MAX_LENGTH = 128


def generate_password(
    length: int = DEFAULT_LENGTH,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """
    Generate a cryptographically secure random password.

    Uses `secrets.choice()` which is backed by the operating system's
    CSPRNG (os.urandom / CryptGenRandom / getrandom).

    The password is guaranteed to contain at least one character from each
    selected character pool, then the remaining characters are filled from
    the combined pool and Fisher-Yates shuffled with secure randomness.

    Args:
        length: Password length (16–128, default 32).
        uppercase: Include A-Z.
        lowercase: Include a-z.
        digits: Include 0-9.
        symbols: Include special characters.

    Returns:
        A cryptographically random password string.

    Raises:
        ValueError: If no character sets are selected or length is invalid.
    """
    if length < MIN_LENGTH:
        length = MIN_LENGTH
    if length > MAX_LENGTH:
        length = MAX_LENGTH

    # Build the alphabet from selected character sets
    alphabet = ""
    required_chars: list[str] = []

    if uppercase:
        alphabet += _UPPERCASE
        required_chars.append(secrets.choice(_UPPERCASE))
    if lowercase:
        alphabet += _LOWERCASE
        required_chars.append(secrets.choice(_LOWERCASE))
    if digits:
        alphabet += _DIGITS
        required_chars.append(secrets.choice(_DIGITS))
    if symbols:
        alphabet += _SYMBOLS
        required_chars.append(secrets.choice(_SYMBOLS))

    if not alphabet:
        raise ValueError("At least one character set must be selected")

    # Fill remaining length with random characters from the combined pool
    remaining = length - len(required_chars)
    if remaining < 0:
        remaining = 0
        required_chars = required_chars[:length]

    password_chars = required_chars + [
        secrets.choice(alphabet) for _ in range(remaining)
    ]

    # Fisher-Yates shuffle using cryptographic randomness
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def evaluate_strength(password: str) -> tuple[int, str, str]:
    """
    Evaluate password strength.

    Returns:
        Tuple of (score 0-100, label, color_hex).
    """
    if not password:
        return (0, "", "#484f58")

    score = 0
    length = len(password)

    # Length scoring (up to 40 points)
    if length >= 32:
        score += 40
    elif length >= 24:
        score += 35
    elif length >= 16:
        score += 28
    elif length >= 12:
        score += 20
    elif length >= 8:
        score += 10
    else:
        score += 5

    # Character diversity scoring (up to 40 points)
    has_upper = any(c in _UPPERCASE for c in password)
    has_lower = any(c in _LOWERCASE for c in password)
    has_digit = any(c in _DIGITS for c in password)
    has_symbol = any(c in _SYMBOLS or c in string.punctuation for c in password)

    diversity = sum([has_upper, has_lower, has_digit, has_symbol])
    score += diversity * 10

    # Entropy bonus (up to 20 points)
    unique_chars = len(set(password))
    if unique_chars >= 20:
        score += 20
    elif unique_chars >= 14:
        score += 15
    elif unique_chars >= 8:
        score += 10
    elif unique_chars >= 5:
        score += 5

    # Cap at 100
    score = min(score, 100)

    # Determine label and color
    if score >= 80:
        return (score, "Very Strong", "#3fb950")
    elif score >= 60:
        return (score, "Strong", "#58a6ff")
    elif score >= 40:
        return (score, "Moderate", "#d29922")
    elif score >= 20:
        return (score, "Weak", "#f85149")
    else:
        return (score, "Very Weak", "#ff4040")
