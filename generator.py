from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

def generate_keys():
    """Generate an RSA public-private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key
    private_key_path = "private_key.pem"
    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    public_key_path = "public_key.pem"
    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Keys generated:\n- Private Key: {private_key_path}\n- Public Key: {public_key_path}")
    return private_key, public_key_path

def sign_message(private_key, message):
    """Sign a message using the private key."""
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Save the message and signature
    message_path = "message.txt"
    with open(message_path, "w") as f:
        f.write(message)

    signature_path = "signature.bin"
    with open(signature_path, "wb") as f:
        f.write(signature)

    print(f"Message signed:\n- Message: {message_path}\n- Signature: {signature_path}")
    return message_path, signature_path

def main():
    # Step 1: Generate Keys
    private_key, public_key_path = generate_keys()

    # Step 2: Define the Message
    message = "This is a proof of ownership for my GitHub repository."

    # Step 3: Sign the Message
    message_path, signature_path = sign_message(private_key, message)

    print("\nFiles ready for upload:")
    print(f"- Public Key: {public_key_path}")
    print(f"- Message: {message_path}")
    print(f"- Signature: {signature_path}")

if __name__ == "__main__":
    main()
