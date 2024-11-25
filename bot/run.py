from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64

def extract_public_key(public_key_path):
    """Extracts the public key from the public_key.pem file"""
    with open(public_key_path, "r") as f:
        content = f.read()
    start = content.find("-----BEGIN PUBLIC KEY-----")
    end = content.find("-----END PUBLIC KEY-----") + len("-----END PUBLIC KEY-----")
    if start == -1 or end == -1:
        raise ValueError("🔴 Public key not found in the specified file!")
    print("📜 Public key extracted successfully from the file!")
    return content[start:end]

def extract_public_key_from_readme(readme_path):
    """Extracts the public key from the README.md file."""
    with open(readme_path, "r") as f:
        content = f.read()
    start = content.find("-----BEGIN PUBLIC KEY-----")
    end = content.find("-----END PUBLIC KEY-----") + len("-----END PUBLIC KEY-----")
    if start == -1 or end == -1:
        raise ValueError("🔴 Public key not found in README.md!")
    print("📜 Public key extracted successfully from README.md!")
    return content[start:end]

def verify_signature(readme_public_key, uploaded_public_key, signature_path, message_path):
    """Verifies a signature if the public key matches the one in the README."""
    print("🔍 Comparing public keys...")
    # Compare public keys
    if readme_public_key.strip() != uploaded_public_key.strip():
        raise ValueError("❌ Uploaded public key does not match the owner's public key in README.md!")
    print("✅ Public keys match! 🎉")

    # Load the public key
    public_key = load_pem_public_key(readme_public_key.encode())
    
    # Load the signature
    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()
    print("📑 Signature file loaded successfully!")
    
    # Load the original message
    with open(message_path, "r") as msg_file:
        message = msg_file.read()
    print("📝 Original message file loaded successfully!")
    
    # Verify the signature
    print("🔑 Verifying the signature...")
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("🎉 Signature is valid! 🟢")
    except Exception as e:
        raise ValueError(f"❌ Signature verification failed: {e}")

# Example usage
readme_path = "public_key.pem"
uploaded_public_key_path = "public_key.pem"
signature_path = "signature.bin"
message_path = "message.txt"

try:
    print("🚀 Starting verification process...")
    # Extract owner's public key from README
    owner_public_key = extract_public_key_from_readme(readme_path)

    # Extract owner's public key from public_key.pem
    uploaded_public_key = extract_public_key(uploaded_public_key_path)

    # Verify the uploaded signature
    verify_signature(owner_public_key, uploaded_public_key, signature_path, message_path)
    print("✅ Verification process completed successfully! 🎊")
except ValueError as e:
    print(f"❌ Error: {e}")
