# encryption-and-dencryption-tool

Sure, here's a step-by-step explanation of the code:

**1. Import Libraries:**

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os
```

- This code imports necessary libraries for cryptographic operations:
    - `cryptography.hazmat.primitives`: Provides cryptographic primitives like hashing and key generation.
    - `cryptography.hazmat.backends`: Specifies the backend to use for cryptographic operations (default_backend is used here).
    - `os`: Used for file path operations.

**2. Key Generation Functions:**

```python
def generate_key_pair(private_key_path='private_key.pem', public_key_path='public_key.pem'):
    """Generates a new RSA key pair and saves them to the specified paths."""
    # ...

def load_private_key(private_key_path='private_key.pem'):
    """Loads an existing private key from the specified path."""
    # ...

def load_public_key(public_key_path='public_key.pem'):
    """Loads an existing public key from the specified path."""
    # ...
```

- These functions handle key generation and loading:
    - `generate_key_pair`: Generates a new RSA key pair (private and public) and saves them to PEM-formatted files at the specified paths (default: private_key.pem and public_key.pem).
    - `load_private_key`: Loads an existing private key from a PEM file.
    - `load_public_key`: Loads an existing public key from a PEM file.

**3. Encryption/Decryption Functions:**

```python
def encrypt_message(message, public_key):
    """Encrypts the given message using the provided public key."""
    # ...

def decrypt_message(encrypted_message, private_key):
    """Decrypts the given message using the provided private key."""
    # ...
```

- These functions perform encryption and decryption:
    - `encrypt_message`: Encrypts a message using the provided public key and returns the encrypted message bytes.
    - `decrypt_message`: Decrypts an encrypted message (bytes) using the provided private key and returns the decrypted message string.

**4. File Encryption/Decryption (using Fernet for symmetric encryption):**

```python
def encrypt_file(file_path, key):
    """Encrypts a file using the provided key."""
    # ...

def decrypt_file(file_path, key):
    """Decrypts a file using the provided key."""
    # ...
```

- These functions (not using the RSA key pair) handle file encryption/decryption using Fernet for symmetric encryption:
    - `encrypt_file`: Encrypts a file using the provided key (assumed to be a symmetric key) and saves the encrypted file with a '.encrypted' extension.
    - `decrypt_file`: Decrypts an encrypted file using the provided key and saves the decrypted file with a '.decrypted' extension.

**5. Menu and Main Loop:**

```python
def print_menu():
    """Prints the main menu options."""
    # ...

if __name__ == "__main__":
    while True:
        # ...
```

- `print_menu`: Prints a menu offering options for generating keys, encrypting/decrypting messages, and exiting.
- The `if __name__ == "__main__":` block runs the main loop:
    - It continuously displays the menu and takes user input.
    - Based on the user's choice, it calls the appropriate functions for key generation, message encryption/decryption, or exits the program.

**Overall, this code provides a tool for RSA asymmetric key encryption/decryption of messages and separate functionality for file encryption/decryption using symmetric encryption (Fernet).**


**Note:**

- This is a simplified example and may require additional error handling and security considerations for real-world use.
- The key generation and encryption/decryption of messages use RSA for asymmetric cryptography, while file encryption/decryption utilizes Fernet for symmetric cryptography. These are separate functionalities within the tool.
