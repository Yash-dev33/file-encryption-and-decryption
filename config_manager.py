"""
Configuration Management System
Handles application settings and user preferences.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ConfigManager:
    """
    Manages application configuration and user settings.
    """
    
    DEFAULT_CONFIG = {
        'encryption': {
            'default_algorithm': 'AES-256-GCM',
            'pbkdf2_iterations': 600000,
            'max_file_size_mb': 1024,
            'secure_delete_passes': 3
        },
        'ui': {
            'theme': 'clam',
            'window_width': 800,
            'window_height': 700,
            'remember_last_algorithm': True,
            'confirm_operations': True
        },
        'security': {
            'min_password_length': 8,
            'require_password_confirmation': True,
            'auto_clear_password': True,
            'save_metadata_by_default': True
        },
        'file_handling': {
            'default_output_suffix': '.encrypted',
            'create_backup_before_delete': False,
            'verify_integrity_after_decryption': True
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Optional path to config file
        """
        if config_path is None:
            # Use user's home directory
            config_dir = Path.home() / '.secure_file_encryption'
            config_dir.mkdir(exist_ok=True)
            config_path = config_dir / 'config.json'
        
        self.config_path = Path(config_path)
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file or create default.
        
        Returns:
            Configuration dictionary
        """
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._merge_config(self.DEFAULT_CONFIG.copy(), loaded_config)
            else:
                # Create default config
                self.save_config(self.DEFAULT_CONFIG)
                return self.DEFAULT_CONFIG.copy()
        except Exception as e:
            logger.error(f"Failed to load config: {type(e).__name__}")
            return self.DEFAULT_CONFIG.copy()
    
    def save_config(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Save configuration to file.
        
        Args:
            config: Configuration dictionary (uses current if None)
            
        Returns:
            bool: True if successful
        """
        try:
            if config is None:
                config = self.config
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Configuration saved: {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {type(e).__name__}")
            return False
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated key path.
        
        Args:
            key_path: Dot-separated key path (e.g., 'encryption.default_algorithm')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> bool:
        """
        Set configuration value by dot-separated key path.
        
        Args:
            key_path: Dot-separated key path
            value: Value to set
            
        Returns:
            bool: True if successful
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent of the final key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        return self.save_config()
    
    def reset_to_defaults(self) -> bool:
        """
        Reset configuration to defaults.
        
        Returns:
            bool: True if successful
        """
        self.config = self.DEFAULT_CONFIG.copy()
        return self.save_config()
    
    @staticmethod
    def _merge_config(base: Dict, update: Dict) -> Dict:
        """
        Recursively merge two configuration dictionaries.
        
        Args:
            base: Base configuration
            update: Configuration to merge in
            
        Returns:
            Merged configuration
        """
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = ConfigManager._merge_config(base[key], value)
            else:
                base[key] = value
        return base


class MetadataManager:
    """
    Manages encryption metadata for files.
    """
    
    @staticmethod
    def create_metadata(original_file: str, algorithm: str, file_size: int,
                       encrypted_size: int, original_hash: str) -> Dict[str, Any]:
        """
        Create metadata dictionary for encrypted file.
        
        Args:
            original_file: Original filename
            algorithm: Encryption algorithm used
            file_size: Original file size
            encrypted_size: Encrypted file size
            original_hash: SHA-256 hash of original file
            
        Returns:
            Metadata dictionary
        """
        import datetime
        
        return {
            'version': '1.0',
            'original_file': original_file,
            'algorithm': algorithm,
            'file_size': file_size,
            'encrypted_size': encrypted_size,
            'original_hash': original_hash,
            'encryption_timestamp': datetime.datetime.now().isoformat(),
            'tool_version': '1.0.0'
        }
    
    @staticmethod
    def verify_integrity(decrypted_data: bytes, metadata: Dict[str, Any]) -> bool:
        """
        Verify integrity of decrypted data against metadata.
        
        Args:
            decrypted_data: Decrypted file data
            metadata: Metadata dictionary
            
        Returns:
            bool: True if integrity check passes
        """
        if 'original_hash' not in metadata:
            logger.warning("No hash in metadata for verification")
            return False
        
        from crypto_engine import CryptoEngine
        computed_hash = CryptoEngine.compute_file_hash(decrypted_data)
        expected_hash = metadata['original_hash']
        
        if computed_hash == expected_hash:
            logger.info("Integrity verification passed")
            return True
        else:
            logger.error("Integrity verification FAILED")
            return False
    
    @staticmethod
    def load_metadata(file_path: str) -> Optional[Dict[str, Any]]:
        """
        Load metadata from JSON file.
        
        Args:
            file_path: Path to metadata file
            
        Returns:
            Metadata dictionary or None
        """
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load metadata: {type(e).__name__}")
            return None
    
    @staticmethod
    def save_metadata(metadata: Dict[str, Any], file_path: str) -> bool:
        """
        Save metadata to JSON file.
        
        Args:
            metadata: Metadata dictionary
            file_path: Output file path
            
        Returns:
            bool: True if successful
        """
        try:
            with open(file_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Metadata saved: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save metadata: {type(e).__name__}")
            return False


class SessionManager:
    """
    Manages encryption/decryption session data.
    """
    
    def __init__(self):
        """Initialize session manager."""
        self.sessions = []
        self.current_session = None
    
    def start_session(self, operation: str, file_count: int) -> Dict[str, Any]:
        """
        Start a new encryption/decryption session.
        
        Args:
            operation: 'encrypt' or 'decrypt'
            file_count: Number of files to process
            
        Returns:
            Session dictionary
        """
        import datetime
        
        session = {
            'id': len(self.sessions) + 1,
            'operation': operation,
            'file_count': file_count,
            'start_time': datetime.datetime.now(),
            'end_time': None,
            'files_processed': 0,
            'files_succeeded': 0,
            'files_failed': 0,
            'status': 'running'
        }
        
        self.sessions.append(session)
        self.current_session = session
        return session
    
    def update_session(self, files_processed: int, success: bool):
        """
        Update current session progress.
        
        Args:
            files_processed: Number of files processed
            success: Whether last file succeeded
        """
        if self.current_session:
            self.current_session['files_processed'] = files_processed
            if success:
                self.current_session['files_succeeded'] += 1
            else:
                self.current_session['files_failed'] += 1
    
    def end_session(self):
        """End current session."""
        import datetime
        
        if self.current_session:
            self.current_session['end_time'] = datetime.datetime.now()
            self.current_session['status'] = 'completed'
            
            # Calculate duration
            duration = (self.current_session['end_time'] - 
                       self.current_session['start_time']).total_seconds()
            self.current_session['duration_seconds'] = duration
    
    def get_session_summary(self) -> Optional[Dict[str, Any]]:
        """
        Get summary of current session.
        
        Returns:
            Session summary or None
        """
        return self.current_session
    
    def get_all_sessions(self) -> list:
        """
        Get all sessions.
        
        Returns:
            List of session dictionaries
        """
        return self.sessions
