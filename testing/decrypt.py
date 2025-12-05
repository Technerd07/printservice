#!/usr/bin/env python3
"""
AES-256-GCM File Decryption Script
Decrypts files encrypted with AES-256-GCM algorithm using metadata from meta.json

Usage:
    python decrypt.py <encrypted_file> <meta_json_file> [output_file]
    
Example:
    python decrypt.py document.pdf.enc meta.json document.pdf
"""

import sys
import json
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESDecryptor:
    """Handle AES-256-GCM decryption with metadata"""
    
    def __init__(self, meta_path: str, encrypted_filename: str = None):
        """
        Initialize decryptor with metadata file
        
        Args:
            meta_path: Path to meta.json file
            encrypted_filename: Name of encrypted file to find in metadata
        """
        self.meta = self._load_metadata(meta_path)
        self.file_meta = self._extract_file_metadata(encrypted_filename)
        self.validate_metadata()
    
    def _load_metadata(self, meta_path: str) -> dict:
        """Load and parse metadata JSON file"""
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Metadata file not found: {meta_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in metadata file: {e}")
    
    def _extract_file_metadata(self, encrypted_filename: str = None) -> dict:
        """
        Extract file-specific metadata from the meta.json structure
        
        Args:
            encrypted_filename: Name of encrypted file (optional)
        
        Returns:
            File metadata dictionary
        """
        # Check if metadata has 'files' array (new structure)
        if 'files' in self.meta and isinstance(self.meta['files'], list):
            if len(self.meta['files']) == 0:
                raise ValueError("No files found in metadata")
            
            # If filename provided, search for matching file
            if encrypted_filename:
                enc_basename = os.path.basename(encrypted_filename)
                for file_meta in self.meta['files']:
                    if file_meta.get('encFilename') == enc_basename:
                        return file_meta
                
                # If not found, use first file
                print(f"Warning: File '{enc_basename}' not found in metadata, using first file")
            
            # Return first file by default
            return self.meta['files'][0]
        
        # Old structure - metadata at root level
        return self.meta
    
    def validate_metadata(self):
        """Validate required fields in metadata"""
        required_fields = ['iv', 'authTag']
        missing = [field for field in required_fields if field not in self.file_meta]
        
        if missing:
            raise ValueError(f"Missing required metadata fields: {', '.join(missing)}")
        
        # Check algorithm at root or file level
        algorithm = self.meta.get('encryption', {}).get('algorithm') or self.file_meta.get('algorithm')
        if algorithm and algorithm != 'aes-256-gcm':
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _decode_base64(self, data: str) -> bytes:
        """Safely decode base64 string"""
        try:
            return base64.b64decode(data)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding: {e}")
    
    def _derive_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """
        Derive AES-256 key from password using PBKDF2
        
        Args:
            password: User password
            salt: Salt bytes (if provided in metadata)
        
        Returns:
            32-byte AES-256 key
        """
        if salt is None:
            # Use default salt if not provided
            salt = b'printease_default_salt_32bytes!!'[:32]
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _unwrap_key(self, master_key: bytes) -> bytes:
        """
        Unwrap the file encryption key using the master key
        
        Args:
            master_key: Master encryption key (32 bytes)
        
        Returns:
            Unwrapped file encryption key
        """
        if 'wrappedKey' not in self.file_meta:
            raise ValueError("No wrapped key found in metadata")
        
        wrapped_key = self._decode_base64(self.file_meta['wrappedKey'])
        wrap_iv = self._decode_base64(self.file_meta['wrapIv'])
        wrap_tag = self._decode_base64(self.file_meta['wrapTag'])
        
        # Combine wrapped key with auth tag
        wrapped_key_with_tag = wrapped_key + wrap_tag
        
        # Unwrap using AESGCM
        aesgcm = AESGCM(master_key)
        try:
            unwrapped_key = aesgcm.decrypt(wrap_iv, wrapped_key_with_tag, None)
            return unwrapped_key
        except Exception as e:
            raise ValueError(f"Failed to unwrap encryption key: {e}")
    
    def decrypt_file(self, encrypted_path: str, output_path: str = None, 
                     password: str = None, key: str = None, master_key: str = None) -> str:
        """
        Decrypt an encrypted file using AES-256-GCM
        
        Args:
            encrypted_path: Path to .enc file
            output_path: Path for decrypted output (optional)
            password: Password for key derivation (if master_key not provided)
            key: Base64-encoded encryption key (direct file key)
            master_key: Base64-encoded master key (for unwrapping)
        
        Returns:
            Path to decrypted file
        """
        # Determine output path
        if output_path is None:
            output_path = encrypted_path.rsplit('.enc', 1)[0]
            if self.file_meta.get('originalName'):
                output_path = os.path.join(
                    os.path.dirname(encrypted_path),
                    self.file_meta['originalName']
                )
        
        # Get encryption key
        if key:
            # Direct file encryption key provided
            encryption_key = self._decode_base64(key)
        elif master_key:
            # Master key provided - unwrap the file key
            master_key_bytes = self._decode_base64(master_key)
            encryption_key = self._unwrap_key(master_key_bytes)
        elif password:
            # Password provided - derive master key and unwrap
            salt = None
            if 'salt' in self.meta:
                salt = self._decode_base64(self.meta['salt'])
            master_key_bytes = self._derive_key_from_password(password, salt)
            encryption_key = self._unwrap_key(master_key_bytes)
        else:
            raise ValueError("Either 'key', 'master_key', or 'password' must be provided")
        
        # Validate key length
        if len(encryption_key) != 32:
            raise ValueError(f"Invalid key length: {len(encryption_key)} bytes (expected 32)")
        
        # Read encrypted data
        try:
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")
        
        # Extract components from metadata
        iv = self._decode_base64(self.file_meta['iv'])
        auth_tag = self._decode_base64(self.file_meta['authTag'])
        
        # Combine encrypted data with auth tag (required by AESGCM)
        ciphertext_with_tag = encrypted_data + auth_tag
        
        # Initialize AESGCM cipher
        aesgcm = AESGCM(encryption_key)
        
        # Decrypt
        try:
            decrypted_data = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        except Exception as e:
            raise ValueError(f"Decryption failed. Possible reasons:\n"
                           f"  - Incorrect key/password\n"
                           f"  - Corrupted encrypted file\n"
                           f"  - Tampered data (auth tag mismatch)\n"
                           f"Error: {e}")
        
        # Write decrypted data
        try:
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
        except Exception as e:
            raise IOError(f"Failed to write decrypted file: {e}")
        
        return output_path
    
    def display_metadata_info(self):
        """Display metadata information"""
        print("\n" + "="*60)
        print("ENCRYPTION METADATA INFORMATION")
        print("="*60)
        
        # Job info
        if 'jobId' in self.meta:
            print(f"Job ID:          {self.meta['jobId']}")
        if 'createdAt' in self.meta:
            print(f"Created At:      {self.meta['createdAt']}")
        
        # Encryption info
        if 'encryption' in self.meta:
            enc = self.meta['encryption']
            print(f"Algorithm:       {enc.get('algorithm', 'N/A')}")
            print(f"Key Length:      {enc.get('keyLength', 'N/A')} bits")
            print(f"IV Length:       {enc.get('ivLength', 'N/A')} bits")
            print(f"Tag Length:      {enc.get('tagLength', 'N/A')} bits")
        
        # File info
        print(f"\nFile Information:")
        print(f"Original Name:   {self.file_meta.get('originalName', 'N/A')}")
        print(f"Safe Name:       {self.file_meta.get('safeName', 'N/A')}")
        print(f"MIME Type:       {self.file_meta.get('mimetype', 'N/A')}")
        print(f"Original Size:   {self.file_meta.get('originalSize', 'N/A')} bytes")
        print(f"Encrypted Size:  {self.file_meta.get('encryptedSize', 'N/A')} bytes")
        
        if 'wrappedKey' in self.file_meta:
            print(f"\nKey Wrapping:    Enabled (wrapped key present)")
        
        if 'uploadedAt' in self.file_meta:
            print(f"Uploaded At:     {self.file_meta['uploadedAt']}")
        
        print("="*60 + "\n")


def main():
    """Main entry point for CLI usage"""
    
    # Print banner
    print("\n" + "="*60)
    print("AES-256-GCM FILE DECRYPTION TOOL")
    print("="*60 + "\n")
    
    # Check arguments
    if len(sys.argv) < 3:
        print("Usage:")
        print(f"  {sys.argv[0]} <encrypted_file> <meta_json> [output_file]")
        print("\nExample:")
        print(f"  {sys.argv[0]} document.pdf.enc meta.json document.pdf")
        print("\nThe script will prompt for the decryption key or password.")
        sys.exit(1)
    
    encrypted_file = sys.argv[1]
    meta_file = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    try:
        # Initialize decryptor
        decryptor = AESDecryptor(meta_file, encrypted_file)
        
        # Display metadata
        decryptor.display_metadata_info()
        
        # Get decryption credentials
        print("Choose decryption method:")
        print("  1. Enter base64-encoded file encryption key (direct)")
        print("  2. Enter base64-encoded master key (unwraps file key)")
        print("  3. Enter password (derives master key, then unwraps)")
        
        choice = input("\nEnter choice (1, 2, or 3): ").strip()
        
        key = None
        master_key = None
        password = None
        
        if choice == '1':
            key = input("Enter base64-encoded file key: ").strip()
            if not key:
                print("Error: Key cannot be empty")
                sys.exit(1)
        elif choice == '2':
            master_key = input("Enter base64-encoded master key: ").strip()
            if not master_key:
                print("Error: Master key cannot be empty")
                sys.exit(1)
        elif choice == '3':
            import getpass
            password = getpass.getpass("Enter password: ")
            if not password:
                print("Error: Password cannot be empty")
                sys.exit(1)
        else:
            print("Error: Invalid choice")
            sys.exit(1)
        
        # Decrypt file
        print("\nDecrypting file...")
        output_path = decryptor.decrypt_file(
            encrypted_file,
            output_file,
            password=password,
            key=key,
            master_key=master_key
        )
        
        # Success message
        print("\n" + "="*60)
        print("✓ DECRYPTION SUCCESSFUL!")
        print("="*60)
        print(f"Decrypted file saved to: {output_path}")
        print(f"File size: {os.path.getsize(output_path)} bytes")
        print("="*60 + "\n")
        
    except Exception as e:
        print("\n" + "="*60)
        print("✗ DECRYPTION FAILED")
        print("="*60)
        print(f"Error: {e}")
        print("="*60 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
