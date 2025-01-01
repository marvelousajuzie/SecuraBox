import secrets

def generate_otp(length=6):
    """Generate a secure OTP of the given length."""
    return str(secrets.randbelow(10000)).zfill(4) 
