"""
Command-Line Interface for Secure File Encryption
For advanced users and automation scenarios.
"""

import argparse
import sys
import os
from pathlib import Path
from getpass import getpass
from file_handler import FileHandler
from crypto_engine import CryptoEngine
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_argparse():
    """Setup command-line argument parser."""
    parser = argparse.ArgumentParser(
        description='Secure File Encryption Tool - Command Line Interface',
        epilog='Example: python cli.py encrypt -i document.pdf -a AES-256-GCM'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt file(s)')
    encrypt_parser.add_argument('-i', '--input', required=True, nargs='+',
                               help='Input file(s) to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file path (single file only)')
    encrypt_parser.add_argument('-a', '--algorithm', default='AES-256-GCM',
                               choices=list(CryptoEngine.ALGORITHMS.keys()),
                               help='Encryption algorithm (default: AES-256-GCM)')
    encrypt_parser.add_argument('-p', '--password', help='Password (not recommended, will prompt if not provided)')
    encrypt_parser.add_argument('-d', '--delete', action='store_true',
                               help='Securely delete original file(s) after encryption')
    encrypt_parser.add_argument('-m', '--metadata', action='store_true', default=True,
                               help='Save encryption metadata (default: True)')
    encrypt_parser.add_argument('--no-metadata', action='store_false', dest='metadata',
                               help='Do not save encryption metadata')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt file(s)')
    decrypt_parser.add_argument('-i', '--input', required=True, nargs='+',
                               help='Input file(s) to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output file path (single file only)')
    decrypt_parser.add_argument('-p', '--password', help='Password (not recommended, will prompt if not provided)')
    decrypt_parser.add_argument('-d', '--delete', action='store_true',
                               help='Securely delete encrypted file(s) after decryption')
    decrypt_parser.add_argument('-v', '--verify', action='store_true', default=True,
                               help='Verify file integrity after decryption (default: True)')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Display encryption information about file')
    info_parser.add_argument('-i', '--input', required=True, help='Encrypted file to inspect')
    
    # Batch command
    batch_parser = subparsers.add_parser('batch', help='Batch process files from list')
    batch_parser.add_argument('-f', '--file', required=True,
                             help='Text file containing list of files (one per line)')
    batch_parser.add_argument('-a', '--action', required=True, choices=['encrypt', 'decrypt'],
                             help='Action to perform on files')
    batch_parser.add_argument('--algorithm', default='AES-256-GCM',
                             choices=list(CryptoEngine.ALGORITHMS.keys()),
                             help='Encryption algorithm (for encrypt action)')
    batch_parser.add_argument('-p', '--password', help='Password (will prompt if not provided)')
    batch_parser.add_argument('-d', '--delete', action='store_true',
                             help='Securely delete original files after processing')
    
    return parser


def get_password(prompt="Enter password: ", confirm=False):
    """
    Securely get password from user.
    
    Args:
        prompt: Password prompt
        confirm: Require password confirmation
        
    Returns:
        Password string or None if cancelled
    """
    try:
        password = getpass(prompt)
        
        if confirm:
            confirm_password = getpass("Confirm password: ")
            if password != confirm_password:
                print("Error: Passwords do not match", file=sys.stderr)
                return None
        
        if len(password) < 8:
            print("Error: Password must be at least 8 characters", file=sys.stderr)
            return None
        
        return password
    except KeyboardInterrupt:
        print("\nOperation cancelled", file=sys.stderr)
        return None


def encrypt_command(args):
    """Handle encrypt command."""
    # Get password
    if args.password:
        print("Warning: Passing password via command line is insecure!", file=sys.stderr)
        password = args.password
    else:
        password = get_password("Enter encryption password: ", confirm=True)
        if not password:
            return 1
    
    # Warn about DES
    if args.algorithm == 'DES':
        print("\n⚠️  WARNING: DES is cryptographically WEAK!", file=sys.stderr)
        print("Use AES-256-GCM for security.", file=sys.stderr)
        response = input("Continue with DES? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Operation cancelled")
            return 0
    
    # Check output path
    if args.output and len(args.input) > 1:
        print("Error: Cannot specify output path for multiple files", file=sys.stderr)
        return 1
    
    # Process files
    print(f"\nEncrypting {len(args.input)} file(s)...")
    success_count = 0
    error_count = 0
    
    for input_file in args.input:
        print(f"\nProcessing: {input_file}")
        
        output_file = args.output if args.output else None
        
        success, message, metadata = FileHandler.encrypt_file(
            input_file,
            password,
            args.algorithm,
            output_path=output_file,
            delete_original=args.delete
        )
        
        if success:
            print(f"✓ {message}")
            success_count += 1
            
            # Save metadata if requested
            if args.metadata and metadata:
                meta_path = (output_file or input_file) + FileHandler.ENCRYPTED_EXTENSION + FileHandler.METADATA_EXTENSION
                if FileHandler.save_metadata(metadata, meta_path):
                    print(f"✓ Metadata saved: {meta_path}")
        else:
            print(f"✗ {message}", file=sys.stderr)
            error_count += 1
    
    # Summary
    print(f"\n{'='*50}")
    print(f"Encryption completed: {success_count} succeeded, {error_count} failed")
    
    return 0 if error_count == 0 else 1


def decrypt_command(args):
    """Handle decrypt command."""
    # Get password
    if args.password:
        print("Warning: Passing password via command line is insecure!", file=sys.stderr)
        password = args.password
    else:
        password = get_password("Enter decryption password: ", confirm=False)
        if not password:
            return 1
    
    # Check output path
    if args.output and len(args.input) > 1:
        print("Error: Cannot specify output path for multiple files", file=sys.stderr)
        return 1
    
    # Process files
    print(f"\nDecrypting {len(args.input)} file(s)...")
    success_count = 0
    error_count = 0
    
    for input_file in args.input:
        print(f"\nProcessing: {input_file}")
        
        output_file = args.output if args.output else None
        
        success, message, metadata = FileHandler.decrypt_file(
            input_file,
            password,
            output_path=output_file,
            verify_integrity=args.verify,
            delete_encrypted=args.delete
        )
        
        if success:
            print(f"✓ {message}")
            success_count += 1
            
            # Display integrity verification result
            if args.verify and metadata:
                print(f"✓ File integrity verified")
        else:
            print(f"✗ {message}", file=sys.stderr)
            error_count += 1
    
    # Summary
    print(f"\n{'='*50}")
    print(f"Decryption completed: {success_count} succeeded, {error_count} failed")
    
    return 0 if error_count == 0 else 1


def info_command(args):
    """Handle info command."""
    try:
        # Read file header
        with open(args.input, 'rb') as f:
            magic = f.read(8)
            if magic != FileHandler.MAGIC_HEADER:
                print("Error: Not a valid encrypted file", file=sys.stderr)
                return 1
            
            import struct
            version = struct.unpack('B', f.read(1))[0]
            algo_id = struct.unpack('B', f.read(1))[0]
            salt = f.read(32)
            param_len = struct.unpack('H', f.read(2))[0]
            param = f.read(param_len)
            data_len = struct.unpack('Q', f.read(8))[0]
        
        # Map algorithm ID
        algo_map = {1: 'AES-256-GCM', 2: 'DES'}
        algorithm = algo_map.get(algo_id, f'Unknown ({algo_id})')
        
        # Get file size
        file_size = os.path.getsize(args.input)
        
        # Display information
        print(f"\n{'='*50}")
        print(f"Encrypted File Information")
        print(f"{'='*50}")
        print(f"File: {args.input}")
        print(f"File Size: {file_size:,} bytes")
        print(f"Format Version: {version}")
        print(f"Algorithm: {algorithm}")
        print(f"Salt Length: {len(salt)} bytes")
        print(f"Nonce/IV Length: {param_len} bytes")
        print(f"Encrypted Data Size: {data_len:,} bytes")
        
        # Try to load metadata
        meta_path = args.input + FileHandler.METADATA_EXTENSION
        if os.path.exists(meta_path):
            print(f"\nMetadata File: {meta_path}")
            metadata = FileHandler.load_metadata(meta_path)
            if metadata:
                print(f"Original File: {metadata.get('original_file', 'Unknown')}")
                print(f"Original Size: {metadata.get('file_size', 'Unknown'):,} bytes")
                print(f"Original Hash: {metadata.get('original_hash', 'Unknown')}")
                print(f"Encryption Date: {metadata.get('encryption_date', 'Unknown')}")
        
        print(f"{'='*50}\n")
        return 0
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def batch_command(args):
    """Handle batch command."""
    try:
        # Read file list
        with open(args.file, 'r') as f:
            files = [line.strip() for line in f if line.strip()]
        
        if not files:
            print("Error: File list is empty", file=sys.stderr)
            return 1
        
        print(f"Found {len(files)} file(s) in batch list")
        
        # Create args for encrypt/decrypt command
        if args.action == 'encrypt':
            class EncryptArgs:
                pass
            cmd_args = EncryptArgs()
            cmd_args.input = files
            cmd_args.output = None
            cmd_args.algorithm = args.algorithm
            cmd_args.password = args.password
            cmd_args.delete = args.delete
            cmd_args.metadata = True
            
            return encrypt_command(cmd_args)
        else:
            class DecryptArgs:
                pass
            cmd_args = DecryptArgs()
            cmd_args.input = files
            cmd_args.output = None
            cmd_args.password = args.password
            cmd_args.delete = args.delete
            cmd_args.verify = True
            
            return decrypt_command(cmd_args)
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def main():
    """Main entry point."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Check if command was provided
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    try:
        if args.command == 'encrypt':
            return encrypt_command(args)
        elif args.command == 'decrypt':
            return decrypt_command(args)
        elif args.command == 'info':
            return info_command(args)
        elif args.command == 'batch':
            return batch_command(args)
        else:
            print(f"Error: Unknown command: {args.command}", file=sys.stderr)
            return 1
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}", file=sys.stderr)
        logger.exception("Unexpected error")
        return 1


if __name__ == '__main__':
    sys.exit(main())
