import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Define the shared secret key for encryption/decryption
shared_secret_key = os.urandom(32)  # 256-bit key

# Define the message data dictionary with messages and timestamps
message_data = {
    "Aman": [
        {"message": "Hey Divyansha, how's it going?", "time": "2023-03-21 10:30:00"},
        {"message": "Not too bad, just working on some coding projects. Did you hear about the new encryption algorithm?", "time": "2023-03-21 10:35:00"},
        {"message": "It's called AES256 and it's supposed to be really secure. Want to give it a try with our messages?", "time": "2023-03-21 10:40:00"},
    ],
    "Divyansha": [
        {"message": "Good, thanks! How about you?", "time": "2023-03-21 10:32:00"},
        {"message": "No, what's that?", "time": "2023-03-21 10:37:00"},
        {"message": "Sure, let's do it!", "time": "2023-03-21 10:42:00"},
    ]
}

# Function to encrypt a message using AES with CBC mode
def encrypt_message(message, key):
    iv = os.urandom(16)  # Initialization vector for CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding the message to a multiple of the block size (16 bytes)
    pad_len = 16 - (len(message) % 16)
    padded_message = message + (chr(pad_len) * pad_len)

    # Encrypt the padded message
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()

    # Return the concatenation of the IV and the ciphertext
    return iv + ciphertext

# Function to decrypt a message using AES with CBC mode
def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]  # Extract the IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and remove padding
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    pad_len = ord(plaintext[-1:])
    plaintext = plaintext[:-pad_len]

    return plaintext.decode()

# Encrypt the messages in the dictionary
for person, messages in message_data.items():
    for message in messages:
        encrypted_message = encrypt_message(message["message"], shared_secret_key)
        message["message"] = encrypted_message.hex()  # Convert to hex for storage

print("Encrypted message_data dictionary:")
print(message_data)

# Decrypt the messages in the dictionary
for person, messages in message_data.items():
    for message in messages:
        ciphertext = bytes.fromhex(message["message"])  # Convert back from hex
        decrypted_message = decrypt_message(ciphertext, shared_secret_key)
        message["message"] = decrypted_message

print("Decrypted message_data dictionary:")
print(message_data)
