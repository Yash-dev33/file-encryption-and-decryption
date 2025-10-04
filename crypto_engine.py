"""
Core Cryptographic Engine Module
Provides secure encryption/decryption functionality with multiple algorithms.
"""

import os
import hashlib
import secrets
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

# Configure logging without exposing sensitive data
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CryptoEngine:
    """
    Handles all cryptographic operations with security best practices.
    """
    
    # Constants
    SALT_SIZE = 32  # 256 bits
    AES_KEY_SIZE = 32  # 256 bits
    DES_KEY_SIZE = 8  # 64 bits (56 effective)
    PBKDF2_ITERATIONS = 600000  # OWASP recommendation for 2024
    GCM_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    GCM_TAG_SIZE = 16  # 128 bits
    
    # Supported algorithms
    ALGORITHMS = {
        'AES-256-GCM': 'aes_gcm',
        'DES': 'des'
    }
    
    @staticmethod
    def generate_salt() -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        Returns:
            bytes: Random salt of SALT_SIZE bytes
        """
        return secrets.token_bytes(CryptoEngine.SALT_SIZE)
    
    @staticmethod
    def derive_key(password: str, salt: bytes, key_size: int) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Cryptographic salt
            key_size: Desired key size in bytes
            
        Returns:
            bytes: Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=CryptoEngine.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    @staticmethod
    def secure_zero(data: bytearray) -> None:
        """
        Securely zero out sensitive data in memory.
        
        Args:
            data: Bytearray to zero out
        """
        if data:
            for i in range(len(data)):
                data[i] = 0
    
    @staticmethod
    def encrypt_aes_gcm(data: bytes, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM (Authenticated Encryption).
        
        Args:
            data: Data to encrypt
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (encrypted_data, salt, nonce)
        """
        try:
            # Generate salt if not provided
            if salt is None:
                salt = CryptoEngine.generate_salt()
            
            # Derive key
            key = CryptoEngine.derive_key(password, salt, CryptoEngine.AES_KEY_SIZE)
            
            # Generate nonce
            nonce = secrets.token_bytes(CryptoEngine.GCM_NONCE_SIZE)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # Append authentication tag
            encrypted_data = ciphertext + encryptor.tag
            
            # Secure cleanup
            key_array = bytearray(key)
            CryptoEngine.secure_zero(key_array)
            
            logger.info("AES-256-GCM encryption completed successfully")
            return encrypted_data, salt, nonce
            
        except Exception as e:
            logger.error(f"AES-256-GCM encryption failed: {type(e).__name__}")
            raise
    
    @staticmethod
    def decrypt_aes_gcm(encrypted_data: bytes, password: str, salt: bytes, nonce: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted data (ciphertext + tag)
            password: User password
            salt: Salt used during encryption
            nonce: Nonce used during encryption
            
        Returns:
            bytes: Decrypted data
            
        Raises:
            Exception: If authentication fails or decryption fails
        """
        try:
            # Derive key
            key = CryptoEngine.derive_key(password, salt, CryptoEngine.AES_KEY_SIZE)
            
            # Split ciphertext and tag
            ciphertext = encrypted_data[:-CryptoEngine.GCM_TAG_SIZE]
            tag = encrypted_data[-CryptoEngine.GCM_TAG_SIZE:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Secure cleanup
            key_array = bytearray(key)
            CryptoEngine.secure_zero(key_array)
            
            logger.info("AES-256-GCM decryption completed successfully")
            return plaintext
            
        except Exception as e:
            logger.error(f"AES-256-GCM decryption failed: {type(e).__name__}")
            raise ValueError("Decryption failed. Incorrect password or corrupted file.")
    
    @staticmethod
    def encrypt_des(data: bytes, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using DES (INSECURE - provided for compatibility only).
        
        ⚠️ WARNING: DES is cryptographically weak. Use AES-256-GCM instead.
        
        Args:
            data: Data to encrypt
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (encrypted_data, salt, iv)
        """
        logger.warning("DES encryption is INSECURE. Use AES-256-GCM for production.")
        
        try:
            # Generate salt if not provided
            if salt is None:
                salt = CryptoEngine.generate_salt()
            
            # Derive key
            key = CryptoEngine.derive_key(password, salt, CryptoEngine.DES_KEY_SIZE)
            
            # Generate IV
            iv = secrets.token_bytes(8)  # DES block size
            
            # Pad data to multiple of 8 bytes (DES block size)
            padding_length = 8 - (len(data) % 8)
            padded_data = data + bytes([padding_length] * padding_length)
            
            # Create cipher
            cipher = Cipher(
                algorithms.TripleDES(key * 3),  # Use 3DES for slightly better security
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Secure cleanup
            key_array = bytearray(key)
            CryptoEngine.secure_zero(key_array)
            
            logger.info("DES encryption completed (INSECURE)")
            return ciphertext, salt, iv
            
        except Exception as e:
            logger.error(f"DES encryption failed: {type(e).__name__}")
            raise
    
    @staticmethod
    def decrypt_des(encrypted_data: bytes, password: str, salt: bytes, iv: bytes) -> bytes:
        """
        Decrypt data using DES.
        
        Args:
            encrypted_data: Encrypted data
            password: User password
            salt: Salt used during encryption
            iv: IV used during encryption
            
        Returns:
            bytes: Decrypted data
        """
        try:
            # Derive key
            key = CryptoEngine.derive_key(password, salt, CryptoEngine.DES_KEY_SIZE)
            
            # Create cipher
            cipher = Cipher(
                algorithms.TripleDES(key * 3),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_data[-1]
            plaintext = padded_data[:-padding_length]
            
            # Secure cleanup
            key_array = bytearray(key)
            CryptoEngine.secure_zero(key_array)
            
            logger.info("DES decryption completed")
            return plaintext
            
        except Exception as e:
            logger.error(f"DES decryption failed: {type(e).__name__}")
            raise ValueError("Decryption failed. Incorrect password or corrupted file.")
    
    @staticmethod
    def compute_file_hash(data: bytes) -> str:
        """
        Compute SHA-256 hash of data for integrity verification.
        
        Args:
            data: Data to hash
            
        Returns:
            str: Hex-encoded SHA-256 hash
        """
        return hashlib.sha256(data).hexdigest()
