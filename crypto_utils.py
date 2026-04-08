from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os


def generate_keys():
    os.makedirs("keys", exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open("keys/private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open("keys/public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    return {
        "status": "success",
        "msg": "RSA public and private keys generated successfully."
    }


def encrypt_file():
    os.makedirs("output", exist_ok=True)

    if not os.path.exists("input_files/sample.txt"):
        return {
            "status": "error",
            "msg": "sample.txt not found inside input_files folder."
        }

    if not os.path.exists("keys/private_key.pem"):
        return {
            "status": "error",
            "msg": "Private key not found. Please generate keys first."
        }

    with open("input_files/sample.txt", "rb") as f:
        data = f.read()

    with open("keys/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    file_hash = digest.finalize()

    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open("output/encrypted_file.bin", "wb") as f:
        f.write(data)

    with open("output/signature.bin", "wb") as f:
        f.write(signature)

    try:
        message_text = data.decode("utf-8")
    except UnicodeDecodeError:
        message_text = str(data)

    return {
        "status": "success",
        "msg": "File processed successfully.",
        "message": message_text,
        "hash": file_hash.hex(),
        "signature": signature.hex()[:120] + "..."
    }


def attack_file():
    encrypted_path = "output/encrypted_file.bin"

    if not os.path.exists(encrypted_path):
        return {
            "status": "error",
            "msg": "Encrypted file not found. Please encrypt file first."
        }

    with open(encrypted_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) == 0:
        return {
            "status": "error",
            "msg": "Encrypted file is empty."
        }

    changed_index = 10 if len(data) > 10 else 0
    old_value = data[changed_index]
    data[changed_index] = (data[changed_index] + 5) % 256
    new_value = data[changed_index]

    with open(encrypted_path, "wb") as f:
        f.write(data)

    return {
        "status": "warning",
        "msg": "Attack simulation completed. File was tampered.",
        "changed_byte_index": changed_index,
        "old_byte_value": old_value,
        "new_byte_value": new_value
    }


def verify_file():
    encrypted_path = "output/encrypted_file.bin"
    signature_path = "output/signature.bin"
    public_key_path = "keys/public_key.pem"

    if not os.path.exists(encrypted_path):
        return {
            "status": "error",
            "msg": "Encrypted file not found. Please encrypt file first."
        }

    if not os.path.exists(signature_path):
        return {
            "status": "error",
            "msg": "Signature file not found. Please encrypt file first."
        }

    if not os.path.exists(public_key_path):
        return {
            "status": "error",
            "msg": "Public key not found. Please generate keys first."
        }

    try:
        with open(encrypted_path, "rb") as f:
            data = f.read()

        with open(signature_path, "rb") as f:
            signature = f.read()

        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        new_hash = digest.finalize()

        public_key.verify(
            signature,
            new_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return {
            "status": "success",
            "msg": "Verification successful. File is secure.",
            "verification_result": "✅ Secure File",
            "received_hash": new_hash.hex()
        }

    except Exception:
        return {
            "status": "danger",
            "msg": "Verification failed. Attack detected.",
            "verification_result": "🚨 ATTACK DETECTED"
        }


def reset_output():
    files_to_remove = [
        "output/encrypted_file.bin",
        "output/signature.bin"
    ]

    removed_any = False

    for file_path in files_to_remove:
        if os.path.exists(file_path):
            os.remove(file_path)
            removed_any = True

    if removed_any:
        return {
            "status": "reset",
            "msg": "Output files cleared successfully."
        }

    return {
        "status": "reset",
        "msg": "Nothing to reset. Output folder was already clear."
    }