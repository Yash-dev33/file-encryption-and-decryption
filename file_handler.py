"""
Secure File Handler Module
Handles file operations with security best practices.
"""

import os
import json
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from crypto_engine import CryptoEngine

logger = logging.getLogger(__name__)


class FileHandler:
    """
    Manages secure file operations for encryption/decryption.
    """
    
    # File format constants
    MAGIC_HEADER = b'SECFILE\x00'  # 8 bytes
    VERSION = 1
    ENCRYPTED_EXTENSION = '.encrypted'
    METADATA_EXTENSION = '.meta'
    
    # Maximum file size (1GB by default)
    MAX_FILE_SIZE = 1024 * 1024 * 1024
    
    @staticmethod
    def validate_file(file_path: str, for_encryption: bool = True) -> Tuple[bool, str]:
        """
        Validate file before processing.
        
        Args:
            file_path: Path to file
            for_encryption: True if validating for encryption, False for decryption
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            path = Path(file_path)
            
            # Check if file exists
            if not path.exists():
                return False, f"File not found: {file_path}"
            
            # Check if it's a file (not directory)
            if not path.is_file():
                return False, f"Not a file: {file_path}"
            
            # Check file size
            file_size = path.stat().st_size
            if file_size == 0:
                return False, "File is empty"
            
            if file_size > FileHandler.MAX_FILE_SIZE:
                size_mb = file_size / (1024 * 1024)
                return False, f"File too large ({size_mb:.1f}MB). Maximum size: {FileHandler.MAX_FILE_SIZE / (1024 * 1024):.0f}MB"
            
            # Check if file is already encrypted (for encryption)
            if for_encryption and ('_encrypted' in path.stem or file_path.endswith(FileHandler.ENCRYPTED_EXTENSION)):
                return False, "File appears to be already encrypted"
            
            # Check if file has encryption header (for decryption)
            if not for_encryption:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    if header != FileHandler.MAGIC_HEADER:
                        return False, "File is not a valid encrypted file"
            
            return True, ""
            
        except PermissionError:
            return False, f"Permission denied: {file_path}"
        except Exception as e:
            return False, f"Validation error: {type(e).__name__}"
    
    @staticmethod
    def read_file(file_path: str) -> bytes:
        """
        Securely read file contents.
        
        Args:
            file_path: Path to file
            
        Returns:
            bytes: File contents
        """
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {type(e).__name__}")
            raise
    
    @staticmethod
    def write_file(file_path: str, data: bytes, overwrite: bool = False) -> bool:
        """
        Securely write data to file.
        
        Args:
            file_path: Path to file
            data: Data to write
            overwrite: Allow overwriting existing file
            
        Returns:
            bool: True if successful
        """
        try:
            path = Path(file_path)
            
            # Check if file exists and overwrite is not allowed
            if path.exists() and not overwrite:
                raise FileExistsError(f"File already exists: {file_path}")
            
            # Write to temporary file first
            temp_path = path.with_suffix(path.suffix + '.tmp')
            with open(temp_path, 'wb') as f:
                f.write(data)
            
            # Rename to final path (atomic operation on most systems)
            temp_path.replace(path)
            
            logger.info(f"File written successfully: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write file {file_path}: {type(e).__name__}")
            raise
    
    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> bool:
        """
        Securely delete file by overwriting before deletion.
        
        Args:
            file_path: Path to file
            passes: Number of overwrite passes
            
        Returns:
            bool: True if successful
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return True
            
            file_size = path.stat().st_size
            
            # Overwrite file multiple times
            with open(file_path, 'wb') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Delete file
            os.remove(file_path)
            logger.info(f"File securely deleted: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to securely delete {file_path}: {type(e).__name__}")
            return False
    
    @staticmethod
    def encrypt_file(file_path: str, password: str, algorithm: str = 'AES-256-GCM',
                    output_path: Optional[str] = None, delete_original: bool = False) -> Tuple[bool, str, Optional[Dict]]:
        """
        Encrypt a file.
        
        Args:
            file_path: Path to file to encrypt
            password: Encryption password
            algorithm: Encryption algorithm
            output_path: Optional output path (defaults to input_path + .encrypted)
            delete_original: Securely delete original file after encryption
            
        Returns:
            Tuple of (success, message, metadata)
        """
        try:
            # Validate file
            is_valid, error_msg = FileHandler.validate_file(file_path, for_encryption=True)
            if not is_valid:
                return False, error_msg, None
            
            # Read file
            logger.info(f"Reading file: {file_path}")
            plaintext = FileHandler.read_file(file_path)
            
            # Compute original file hash
            original_hash = CryptoEngine.compute_file_hash(plaintext)
            
            # Encrypt based on algorithm
            if algorithm == 'AES-256-GCM':
                encrypted_data, salt, nonce = CryptoEngine.encrypt_aes_gcm(plaintext, password)
                algo_id = 1
                param = nonce
            elif algorithm == 'DES':
                encrypted_data, salt, iv = CryptoEngine.encrypt_des(plaintext, password)
                algo_id = 2
                param = iv
            else:
                return False, f"Unsupported algorithm: {algorithm}", None
            
            # Create output path - keep original extension
            if output_path is None:
                path = Path(file_path)
                # Insert '_encrypted' before the extension
                if path.suffix:
                    base_output = str(path.with_name(path.stem + '_encrypted' + path.suffix))
                else:
                    base_output = file_path + '_encrypted'
                
                # Check if file exists and auto-increment
                output_path = base_output
                counter = 1
                while Path(output_path).exists():
                    if path.suffix:
                        output_path = str(path.with_name(path.stem + f'_encrypted_{counter}' + path.suffix))
                    else:
                        output_path = file_path + f'_encrypted_{counter}'
                    counter += 1
            
            # Build encrypted file structure
            # Header: MAGIC(8) + VERSION(1) + ALGO(1) + SALT(32) + PARAM_LEN(2) + PARAM + DATA_LEN(8) + DATA
            header = FileHandler.MAGIC_HEADER
            header += struct.pack('B', FileHandler.VERSION)
            header += struct.pack('B', algo_id)
            header += salt
            header += struct.pack('H', len(param))
            header += param
            header += struct.pack('Q', len(encrypted_data))
            
            # Write encrypted file
            FileHandler.write_file(output_path, header + encrypted_data)
            
            # Create metadata
            metadata = {
                'original_file': os.path.basename(file_path),
                'algorithm': algorithm,
                'file_size': len(plaintext),
                'encrypted_size': len(encrypted_data),
                'original_hash': original_hash,
                'encryption_date': str(os.path.getmtime(file_path))
            }
            
            # Securely delete original if requested
            if delete_original:
                FileHandler.secure_delete(file_path)
                logger.info(f"Original file securely deleted: {file_path}")
            
            return True, f"File encrypted successfully: {output_path}", metadata
            
        except Exception as e:
            logger.error(f"Encryption failed for {file_path}: {type(e).__name__}")
            return False, f"Encryption failed: {str(e)}", None
    
    @staticmethod
    def decrypt_file(file_path: str, password: str, output_path: Optional[str] = None,
                    verify_integrity: bool = True, delete_encrypted: bool = False) -> Tuple[bool, str, Optional[Dict]]:
        """
        Decrypt a file.
        
        Args:
            file_path: Path to encrypted file
            password: Decryption password
            output_path: Optional output path (defaults to removing .encrypted extension)
            verify_integrity: Verify file integrity after decryption
            delete_encrypted: Securely delete encrypted file after decryption
            
        Returns:
            Tuple of (success, message, metadata)
        """
        try:
            # Validate file
            is_valid, error_msg = FileHandler.validate_file(file_path, for_encryption=False)
            if not is_valid:
                return False, error_msg, None
            
            # Read encrypted file
            logger.info(f"Reading encrypted file: {file_path}")
            with open(file_path, 'rb') as f:
                # Read header
                magic = f.read(8)
                if magic != FileHandler.MAGIC_HEADER:
                    return False, "Invalid file format", None
                
                version = struct.unpack('B', f.read(1))[0]
                if version != FileHandler.VERSION:
                    return False, f"Unsupported file version: {version}", None
                
                algo_id = struct.unpack('B', f.read(1))[0]
                salt = f.read(32)
                param_len = struct.unpack('H', f.read(2))[0]
                param = f.read(param_len)
                data_len = struct.unpack('Q', f.read(8))[0]
                encrypted_data = f.read(data_len)
            
            # Decrypt based on algorithm
            if algo_id == 1:  # AES-256-GCM
                plaintext = CryptoEngine.decrypt_aes_gcm(encrypted_data, password, salt, param)
                algorithm = 'AES-256-GCM'
            elif algo_id == 2:  # DES
                plaintext = CryptoEngine.decrypt_des(encrypted_data, password, salt, param)
                algorithm = 'DES'
            else:
                return False, f"Unknown algorithm ID: {algo_id}", None
            
            # Create output path - remove '_encrypted' from filename
            if output_path is None:
                path = Path(file_path)
                # Remove '_encrypted' from the filename before extension
                if '_encrypted' in path.stem:
                    new_stem = path.stem.replace('_encrypted', '')
                    base_output = str(path.with_name(new_stem + path.suffix))
                elif file_path.endswith(FileHandler.ENCRYPTED_EXTENSION):
                    # Fallback for old .encrypted extension
                    base_output = file_path[:-len(FileHandler.ENCRYPTED_EXTENSION)]
                else:
                    base_output = file_path + '.decrypted'
                
                # Check if file exists and auto-increment
                output_path = base_output
                counter = 1
                path_obj = Path(base_output)
                while Path(output_path).exists():
                    if path_obj.suffix:
                        output_path = str(path_obj.with_name(path_obj.stem + f'_{counter}' + path_obj.suffix))
                    else:
                        output_path = base_output + f'_{counter}'
                    counter += 1
            
            # Write decrypted file
            FileHandler.write_file(output_path, plaintext)
            
            # Compute decrypted file hash for verification
            decrypted_hash = CryptoEngine.compute_file_hash(plaintext)
            
            # Create metadata
            metadata = {
                'algorithm': algorithm,
                'decrypted_file': output_path,
                'file_size': len(plaintext),
                'decrypted_hash': decrypted_hash
            }
            
            # Securely delete encrypted file if requested
            if delete_encrypted:
                FileHandler.secure_delete(file_path)
                logger.info(f"Encrypted file securely deleted: {file_path}")
            
            return True, f"File decrypted successfully: {output_path}", metadata
            
        except ValueError as e:
            logger.error(f"Decryption failed for {file_path}: Incorrect password or corrupted file")
            return False, "Decryption failed: Incorrect password or corrupted file", None
        except Exception as e:
            logger.error(f"Decryption failed for {file_path}: {type(e).__name__}")
            return False, f"Decryption failed: {str(e)}", None
    
    @staticmethod
    def batch_encrypt(file_paths: List[str], password: str, algorithm: str = 'AES-256-GCM',
                     delete_original: bool = False) -> List[Tuple[str, bool, str]]:
        """
        Encrypt multiple files.
        
        Args:
            file_paths: List of file paths to encrypt
            password: Encryption password
            algorithm: Encryption algorithm
            delete_original: Securely delete original files after encryption
            
        Returns:
            List of tuples (file_path, success, message)
        """
        results = []
        for file_path in file_paths:
            success, message, _ = FileHandler.encrypt_file(
                file_path, password, algorithm, delete_original=delete_original
            )
            results.append((file_path, success, message))
        return results
    
    @staticmethod
    def batch_decrypt(file_paths: List[str], password: str, delete_encrypted: bool = False) -> List[Tuple[str, bool, str]]:
        """
        Decrypt multiple files.
        
        Args:
            file_paths: List of file paths to decrypt
            password: Decryption password
            delete_encrypted: Securely delete encrypted files after decryption
            
        Returns:
            List of tuples (file_path, success, message)
        """
        results = []
        for file_path in file_paths:
            success, message, _ = FileHandler.decrypt_file(
                file_path, password, delete_encrypted=delete_encrypted
            )
            results.append((file_path, success, message))
        return results
    
    @staticmethod
    def save_metadata(metadata: Dict, output_path: str) -> bool:
        """
        Save encryption metadata to JSON file.
        
        Args:
            metadata: Metadata dictionary
            output_path: Output file path
            
        Returns:
            bool: True if successful
        """
        try:
            with open(output_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Metadata saved: {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save metadata: {type(e).__name__}")
            return False
    
    @staticmethod
    def load_metadata(file_path: str) -> Optional[Dict]:
        """
        Load encryption metadata from JSON file.
        
        Args:
            file_path: Path to metadata file
            
        Returns:
            Dictionary with metadata or None if failed
        """
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load metadata: {type(e).__name__}")
            return None
