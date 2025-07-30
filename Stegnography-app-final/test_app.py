import pytest
from app import aes_encrypt, aes_decrypt, generate_key

def test_aes_encryption():
    key, _ = generate_key()
    message = "Test Message"
    encrypted = aes_encrypt(message, key)
    decrypted = aes_decrypt(encrypted, key)
    assert decrypted == message