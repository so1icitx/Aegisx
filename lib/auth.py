import pyotp
import qrcode
import base64
import secrets
from io import BytesIO
import os

# Generate or retrieve CSRF token from session
def generate_csrf_token(session):
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

# Verify CSRF token from request (form or header)
def verify_csrf_token(request, session):
    form_token = request.form.get("_csrf_token")
    header_token = request.headers.get("X-CSRFToken")
    session_token = session.get("_csrf_token")

    if not session_token:
        return False

    return form_token == session_token or header_token == session_token

# Check if 2FA is enabled
def check_2fa_enabled():
    return os.path.exists("2fa_secret.txt")

# Verify 2FA code against stored secret
def verify_2fa_code(code):
    if not os.path.exists("2fa_secret.txt"):
        return False

    with open("2fa_secret.txt", "r") as f:
        secret = f.read().strip()

    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

# Generate 2FA QR code and secret
def generate_2fa_qr():
    secret = pyotp.random_base32()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name="AegisX",
        issuer_name="AegisX"
    )

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return (secret, f"data:image/png;base64,{qr_base64}")

# Save 2FA secret to file
def enable_2fa(secret):
    with open("2fa_secret.txt", "w") as f:
        f.write(secret)

# Remove 2FA secret file
def disable_2fa():
    if os.path.exists("2fa_secret.txt"):
        os.remove("2fa_secret.txt")
