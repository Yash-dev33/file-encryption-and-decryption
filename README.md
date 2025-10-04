# 🔒 Secure File Encryption Tool

A production-ready Python desktop application for secure file encryption and decryption with a user-friendly graphical interface.

## Features

### 🛡️ Security Features
- **AES-256-GCM**: Industry-standard authenticated encryption
- **DES Support**: For legacy compatibility (with security warnings)
- **PBKDF2 Key Derivation**: 600,000 iterations using SHA-256
- **Cryptographically Secure Salts**: Unique salt for each encryption
- **Authenticated Encryption**: Prevents tampering with encrypted files
- **Secure Memory Cleanup**: Zeros out sensitive data after use
- **Secure File Deletion**: Multi-pass overwrite before deletion

### 💻 User Interface
- Clean, professional Windows-style GUI 
- Standard Windows controls and familiar layout
- Multi-file selection support
- Algorithm selection dropdown
- Password visibility toggle
- Collapsible log viewer with window auto-resize
- Batch processing support
- Auto-clearing form after operations

### 🔧 Advanced Features
- Smart file naming (preserves original extensions)
- Auto-increment for duplicate filenames
- File integrity verification with SHA-256 hashing
- Batch encrypt/decrypt operations
- Optional secure deletion of original files
- Threaded processing for UI responsiveness
- Encryption metadata tracking

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup

1. Clone or download this repository:
```bash
cd "d:\file encry"
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Application

```bash
python gui_app.py
```

### Encrypting Files

1. Select **"Encrypt Files"** operation (default)
2. Click **"Add Files..."** to select files to encrypt
3. Choose encryption algorithm (AES-256-GCM recommended)
4. Enter a strong password (minimum 8 characters)
5. Confirm the password
6. Optionally enable "Securely delete original files after processing"
7. Click **"START"**
8. View results in the log (click "Show Log" to expand)

### Decrypting Files

1. Select **"Decrypt Files"** operation
2. Click **"Add Files"** to select encrypted files (*_encrypted.*)
3. Enter the password used during encryption (no confirmation needed)
4. Optionally enable secure deletion of encrypted files
5. Click **"START"**

### File Naming Convention

Encrypted files preserve the original extension:
- `document.pdf` → `document_encrypted.pdf`
- `photo.jpg` → `photo_encrypted.jpg`
- If file exists: `photo_encrypted_1.jpg`, `photo_encrypted_2.jpg`, etc.

### File Format

Encrypted files use a custom binary format:
```
[MAGIC HEADER][VERSION][ALGORITHM][SALT][PARAM_LEN][NONCE/IV][DATA_LEN][ENCRYPTED DATA]
```

- Magic Header: `SECFILE\x00` (8 bytes)
- Version: Format version (1 byte)
- Algorithm: 1=AES-256-GCM, 2=DES (1 byte)
- Salt: 32 bytes (PBKDF2 salt)
- Param Length: 2 bytes (length of nonce/IV)
- Nonce/IV: Variable length (12 bytes for GCM, 8 for DES)
- Data Length: 8 bytes (uint64)
- Encrypted Data: Variable length

## Security Best Practices

### Password Guidelines
- Use at least 12 characters
- Include uppercase and lowercase letters
- Include numbers and special characters
- Don't reuse passwords across files
- Consider using a password manager

### Algorithm Selection
- **AES-256-GCM**: Use for all new encryptions (recommended)
- **DES**: Only for legacy compatibility (not recommended)

### File Handling
- Always verify decryption with integrity checks
- Use secure deletion for sensitive originals
- Keep backup copies of encrypted files
- Store metadata files separately from encrypted files

### Important Warnings
⚠️ **Password Recovery**: There is NO way to recover files if you forget the password. Store passwords securely!

⚠️ **Secure Deletion**: When enabled, original files are permanently destroyed and cannot be recovered.

⚠️ **DES Algorithm**: DES is cryptographically weak. Only use for compatibility with legacy systems.

## Architecture

### Core Modules

#### `crypto_engine.py`
Cryptographic operations engine:
- Key derivation (PBKDF2-HMAC-SHA256)
- AES-256-GCM encryption/decryption
- DES encryption/decryption
- Secure memory cleanup
- File hash computation

#### `file_handler.py`
Secure file operations:
- File validation
- Encrypted file format handling
- Secure file deletion
- Batch processing
- Metadata management

#### `gui_app.py`
Graphical user interface:
- File selection interface
- Progress tracking
- Operation logging
- Multi-threaded processing

#### `config_manager.py`
Configuration and settings:
- User preferences
- Security settings
- Algorithm configuration
- Session management

#### `cli.py`
Command-line interface:
- Terminal-based encryption/decryption
- Batch processing
- Scripting support
- Advanced options

## Configuration

The application stores configuration in:
```
%USERPROFILE%\.secure_file_encryption\config.json
```

### Default Configuration

```json
{
  "encryption": {
    "default_algorithm": "AES-256-GCM",
    "pbkdf2_iterations": 600000,
    "max_file_size_mb": 1024,
    "secure_delete_passes": 3
  },
  "ui": {
    "theme": "vista",
    "window_width": 300,
    "window_height": 620,
    "window_width_expanded": 600,
    "window_height_expanded": 700
  },
  "security": {
    "min_password_length": 8,
    "require_password_confirmation_encrypt": true,
    "require_password_confirmation_decrypt": false
  }
}
```

## Technical Specifications

### Encryption Algorithms

#### AES-256-GCM
- **Key Size**: 256 bits
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **Nonce**: 96 bits (cryptographically random)
- **Authentication Tag**: 128 bits
- **Security Level**: Military-grade, NIST approved

#### DES (Legacy)
- **Key Size**: 56 bits effective (64 bits with parity)
- **Mode**: CBC (Cipher Block Chaining)
- **IV**: 64 bits (cryptographically random)
- **Security Level**: Weak, use only for compatibility

### Key Derivation

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000 (OWASP 2024 recommendation)
- **Salt Size**: 256 bits (cryptographically random)
- **Output**: 256 bits for AES, 64 bits for DES

## Error Handling

The application handles:
- Invalid passwords
- Corrupted files
- Missing files
- Insufficient permissions
- Large file scenarios
- Memory constraints
- Authentication failures

All errors are logged without exposing sensitive information.

## Performance

### Benchmarks (Approximate)
- **Small files** (<1MB): < 1 second
- **Medium files** (1-100MB): 1-10 seconds
- **Large files** (100MB-1GB): 10-60 seconds

Performance depends on:
- File size
- CPU speed
- Disk I/O speed
- Available memory

### Limitations
- Maximum file size: 1GB (configurable)
- Memory usage: ~2x file size during processing
- GUI responsiveness maintained via threading

## Troubleshooting

### "Decryption failed: Incorrect password or corrupted file"
- Verify password is correct
- Check if file is corrupted
- Ensure file hasn't been modified
- Verify file format is valid

### "File too large"
- Adjust `max_file_size_mb` in configuration
- Split large files before encryption
- Use command-line tools for very large files

### "Permission denied"
- Run with appropriate file system permissions
- Check file is not locked by another process
- Verify write permissions for output directory

## Development

### Project Structure
```
d:\file encry\
├── crypto_engine.py      # Cryptographic operations
├── file_handler.py       # File operations & validation
├── gui_app.py            # Main GUI application (Rufus-style)
├── cli.py                # Command-line interface
├── config_manager.py     # Configuration management
├── launch.bat            # Windows launcher script
├── requirements.txt      # Python dependencies
├── README.md             # This file
```

### Contributing
Contributions are welcome! Please:
1. Follow secure coding practices
2. Add tests for new features
3. Update documentation
4. Follow PEP 8 style guidelines

## License

This project is provided as-is for educational and personal use. 

## Disclaimer

⚠️ **Important**: This software is provided "as is" without warranty of any kind. The developers are not responsible for data loss, security breaches, or any other damages resulting from the use of this software.

- Always keep backup copies of important files
- Test encryption/decryption before relying on it
- Use at your own risk
- Comply with local laws regarding encryption

## Security Compliance

This application implements cryptographic best practices as of 2025:
- ✓ OWASP password storage guidelines
- ✓ NIST encryption standards
- ✓ Authenticated encryption (AEAD)
- ✓ Secure key derivation
- ✓ Cryptographically secure random generation
- ✓ Memory security practices

## Contact & Support

For issues, questions, or suggestions:
- Check the troubleshooting section
- Review error logs in the GUI
- Consult cryptography library documentation

## Version History

### Version 1.0.0 (October 2025)
- Professional Rufus-style GUI interface
- AES-256-GCM encryption (primary)
- DES legacy support
- Smart file naming with extension preservation
- Auto-increment for duplicate filenames
- Collapsible log viewer with auto-resize
- Batch processing support
- Optional secure file deletion
- Command-line interface (CLI)
- Comprehensive test suite
- Multi-threaded processing

## Acknowledgments

Built with:
- [Python Cryptography Library](https://cryptography.io/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html)
- NIST cryptographic standards
- OWASP security guidelines

---

**Remember**: Strong encryption is only as good as your password. Use strong, unique passwords and store them securely! 🔐
