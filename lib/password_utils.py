import string
import secrets as pysecrets
import re

# Generate a random password based on specified criteria
def create_password(length=16, include_upper=True, include_lower=True,
                    include_numbers=True, include_symbols=True):
    try:
        length = int(length)
    except ValueError:
        length = 16
    if length < 0 or length > 64:
        length = 16

    charset = ""
    if include_upper:   charset += string.ascii_uppercase
    if include_lower:   charset += string.ascii_lowercase
    if include_numbers: charset += string.digits
    if include_symbols: charset += "!@#$%^&*()_+-=[]{};:\'\",.<>?/\\|`~]"

    if not charset:
        charset = string.ascii_letters + string.digits

    return ''.join(pysecrets.choice(charset) for _ in range(length))

# Check password strength using regex patterns
def check_password_strength(password, check_breach_func):
    if not password:
        return 'weak'

    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'\",.<>?/\\|`~]', password))

    is_breached, _ = check_breach_func(password)

    if is_breached:
        return 'breached'

    if length >= 8 and has_upper and has_lower and has_digit and has_special:
        return 'strong'

    return 'weak'
