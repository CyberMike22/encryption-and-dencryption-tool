from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os

def generate_key_pair(private_key_path='private_key.pem', public_key_path='public_key.pem'):
    """Generates a new RSA key pair and saves them to the specified paths."""
    try:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Generate public key
        public_key = private_key.public_key()
        
        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
        return private_key, public_key
    except Exception as e:
        raise Exception(f"Error generating keys: {str(e)}")

def load_private_key(private_key_path='private_key.pem'):
    """Loads an existing private key from the specified path."""
    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        raise Exception("Private key file not found. Generate keys first.")
    except Exception as e:
        raise Exception(f"Error loading private key: {str(e)}")

def load_public_key(public_key_path='public_key.pem'):
    """Loads an existing public key from the specified path."""
    try:
        with open(public_key_path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except FileNotFoundError:
        raise Exception("Public key file not found. Generate keys first.")
    except Exception as e:
        raise Exception(f"Error loading public key: {str(e)}")

def encrypt_message(message, public_key):
    """Encrypts the given message using the provided public key."""
    try:
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message
    except Exception as e:
        raise Exception(f"Error encrypting message: {str(e)}")

def decrypt_message(encrypted_message, private_key):
    """Decrypts the given message using the provided private key."""
    try:
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()
    except Exception as e:
        raise Exception(f"Error decrypting message: {str(e)}")

def encrypt_file(file_path, key):
    """Encrypts a file using the provided key."""
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)
        with open(f"{file_path}.encrypted", 'wb') as file:
            file.write(encrypted_data)
        return f"{file_path}.encrypted"
    except Exception as e:
        raise Exception(f"Error encrypting file: {str(e)}")

def decrypt_file(file_path, key):
    """Decrypts a file using the provided key."""
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        output_path = file_path.replace('.encrypted', '.decrypted')
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)
        return output_path
    except Exception as e:
        raise Exception(f"Error decrypting file: {str(e)}")

def print_menu():
    """Prints the main menu options."""
    print("\n=== Asymmetric Encryption Tool ===")
    print("1. Generate Key Pair")
    print("2. Encrypt Message (using public key)")
    print("3. Decrypt Message (using private key)")
    print("4. Exit")
    return input("\nChoose an option: ")

if __name__ == "__main__":
    while True:
        try:
            choice = print_menu()

            if choice == '1':
                private_key_path = input("Enter private key file path (or press Enter for default 'private_key.pem'): ")
                public_key_path = input("Enter public key file path (or press Enter for default 'public_key.pem'): ")
                
                private_key_path = private_key_path if private_key_path else 'private_key.pem'
                public_key_path = public_key_path if public_key_path else 'public_key.pem'
                
                private_key, public_key = generate_key_pair(private_key_path, public_key_path)
                print(f"Key pair generated successfully!")
                print(f"Private key saved at: {private_key_path}")
                print(f"Public key saved at: {public_key_path}")

            elif choice == '2':
                public_key = load_public_key()
                message = input("Enter message to encrypt: ")
                encrypted_msg = encrypt_message(message, public_key)
                print("Encrypted message (copy this):", encrypted_msg.hex())

            elif choice == '3':
                private_key = load_private_key()
                try:
                    encrypted_msg = bytes.fromhex(input("Enter encrypted message (hex): "))
                    decrypted_msg = decrypt_message(encrypted_msg, private_key)
                    print("Decrypted message:", decrypted_msg)
                except ValueError:
                    print("Error: Invalid encrypted message format. Make sure to copy the exact encrypted message.")

            elif choice == '4':
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please try again.")

        except Exception as e:
            print(f"Error: {str(e)}")
            print("Please try again.")