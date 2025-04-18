#Copyright 2025 Henry Xue
#SPDX-License-Identifier: Apache-2.0
import argparse
import configparser
import getpass
import hashlib
import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

CONFIG_FILE = 'config.ini'
config = configparser.ConfigParser()

# Default values
DEFAULT_PBKDF2_ITERATIONS = 600000
DEFAULT_KEY_LENGTH_BYTES = 32
DEFAULT_SALT_LENGTH_BYTES = 16
DEFAULT_LENGTH_FIELD_BYTES = 4
DEFAULT_FILENAME_LEN_BYTES = 1
DEFAULT_NONCE_LENGTH_BYTES = 12  # Standard for AES-GCM
DEFAULT_TAG_LENGTH_BYTES = 16  # Standard for AES-GCM

PBKDF2_ITERATIONS = DEFAULT_PBKDF2_ITERATIONS
KEY_LENGTH_BYTES = DEFAULT_KEY_LENGTH_BYTES
SALT_LENGTH_BYTES = DEFAULT_SALT_LENGTH_BYTES
LENGTH_FIELD_BYTES = DEFAULT_LENGTH_FIELD_BYTES
FILENAME_LEN_BYTES = DEFAULT_FILENAME_LEN_BYTES
NONCE_LENGTH_BYTES = DEFAULT_NONCE_LENGTH_BYTES
TAG_LENGTH_BYTES = DEFAULT_TAG_LENGTH_BYTES


def load_config():
    global PBKDF2_ITERATIONS, KEY_LENGTH_BYTES, SALT_LENGTH_BYTES
    global LENGTH_FIELD_BYTES, FILENAME_LEN_BYTES
    global NONCE_LENGTH_BYTES, TAG_LENGTH_BYTES

    print(f"Loading configuration from '{CONFIG_FILE}'...")
    if not os.path.exists(CONFIG_FILE):
        print(f"Warning: Configuration file '{CONFIG_FILE}' not found. Using default values.")
        return

    try:
        read_files = config.read(CONFIG_FILE)
        if not read_files:
            print(f"Warning: Could not read configuration file '{CONFIG_FILE}'. Using default values.")
            return

        # Read values, falling back to defaults if missing/invalid
        PBKDF2_ITERATIONS = config.getint('Crypto', 'PBKDF2_ITERATIONS', fallback=DEFAULT_PBKDF2_ITERATIONS)
        KEY_LENGTH_BYTES = config.getint('Crypto', 'KEY_LENGTH_BYTES', fallback=DEFAULT_KEY_LENGTH_BYTES)
        SALT_LENGTH_BYTES = config.getint('Crypto', 'SALT_LENGTH_BYTES', fallback=DEFAULT_SALT_LENGTH_BYTES)

        LENGTH_FIELD_BYTES = config.getint('Steganography', 'LENGTH_FIELD_BYTES', fallback=DEFAULT_LENGTH_FIELD_BYTES)
        FILENAME_LEN_BYTES = config.getint('Steganography', 'FILENAME_LEN_BYTES', fallback=DEFAULT_FILENAME_LEN_BYTES)

        # NONCE_LENGTH_BYTES = config.getint('Crypto', 'NONCE_LENGTH_BYTES', fallback=DEFAULT_NONCE_LENGTH_BYTES)
        # TAG_LENGTH_BYTES = config.getint('Crypto', 'TAG_LENGTH_BYTES', fallback=DEFAULT_TAG_LENGTH_BYTES)

        if PBKDF2_ITERATIONS < 1000: print("Warning: PBKDF2_ITERATIONS is very low in config.")
        if KEY_LENGTH_BYTES not in [16, 24, 32]: print("Warning: KEY_LENGTH_BYTES should be 16, 24, or 32.")
        if not 1 <= FILENAME_LEN_BYTES <= 2: print("Warning: FILENAME_LEN_BYTES should typically be 1 or 2.")

        print("Configuration loaded successfully.")

    except (configparser.Error, ValueError) as e:
        print(f"Error reading configuration file '{CONFIG_FILE}': {e}. Using default values.")
        PBKDF2_ITERATIONS = DEFAULT_PBKDF2_ITERATIONS
        KEY_LENGTH_BYTES = DEFAULT_KEY_LENGTH_BYTES
        SALT_LENGTH_BYTES = DEFAULT_SALT_LENGTH_BYTES
        LENGTH_FIELD_BYTES = DEFAULT_LENGTH_FIELD_BYTES
        FILENAME_LEN_BYTES = DEFAULT_FILENAME_LEN_BYTES
        NONCE_LENGTH_BYTES = DEFAULT_NONCE_LENGTH_BYTES
        TAG_LENGTH_BYTES = DEFAULT_TAG_LENGTH_BYTES


def derive_key_kdf(passphrase: str, salt: bytes) -> bytes:
    """Derives a key using PBKDF2-HMAC-SHA256."""
    print(f"Deriving key using PBKDF2 (Iterations: {PBKDF2_ITERATIONS})... This may take a moment.")
    key = hashlib.pbkdf2_hmac(
        'sha256', passphrase.encode('utf-8'), salt,
        PBKDF2_ITERATIONS, dklen=KEY_LENGTH_BYTES
    )
    print("Key derived successfully.")
    return key


def encrypt_message(key: bytes, plaintext_bytes: bytes) -> bytes:
    """Encrypts message using AES-GCM. Returns nonce + ciphertext + tag."""
    nonce = os.urandom(NONCE_LENGTH_BYTES)  # Uses config value
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
    encrypted_data = nonce + ciphertext_with_tag
    return encrypted_data


def decrypt_message(key: bytes, encrypted_data_with_nonce: bytes) -> bytes:
    """Decrypts AES-GCM encrypted data (nonce + ciphertext + tag)."""
    if len(encrypted_data_with_nonce) < NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES:  # Uses config values
        raise ValueError("Encrypted data is too short to contain nonce and tag.")
    nonce = encrypted_data_with_nonce[:NONCE_LENGTH_BYTES]
    ciphertext_with_tag = encrypted_data_with_nonce[NONCE_LENGTH_BYTES:]
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return plaintext_bytes
    except Exception as e:
        raise ValueError("Decryption failed. Incorrect passphrase or corrupted data.")


def data_to_bits(data: bytes):
    """Convert bytes to a generator of bits (MSB first)."""
    for byte in data:
        for i in range(8):
            yield (byte >> (7 - i)) & 1


def bits_to_bytes(bits) -> bytes:
    """Convert an iterable of bits back to bytes."""
    byte_list = []
    current_byte = 0
    bit_count = 0
    try:
        for bit in bits:
            current_byte = (current_byte << 1) | bit
            bit_count += 1
            if bit_count == 8:
                byte_list.append(current_byte)
                current_byte = 0
                bit_count = 0
    except StopIteration:
        pass
    return bytes(byte_list)


def extract_bits_generator(image_path: str):
    """Generator that yields LSBs (R, G, B order) from an image."""
    try:
        with Image.open(image_path) as img_raw:
            img = img_raw.convert('RGB')
    except FileNotFoundError:
        print(f"Error: Stego image file not found: {image_path}")
        raise StopIteration
    except Exception as e:
        print(f"Error opening or converting image {image_path}: {e}")
        raise StopIteration
    width, height = img.size
    pixels = img.load()
    try:
        for y in range(height):
            for x in range(width):
                pixel_val = pixels[x, y]
                if isinstance(pixel_val, tuple) and len(pixel_val) == 3:
                    r, g, b = pixel_val
                    yield r & 1
                    yield g & 1
                    yield b & 1
                else:
                    pass
    except Exception as e:
        print(f"\nWarning: Error accessing pixel data ({e}).")


def _embed_data_lsb(image_path: str, data_to_hide: bytes, output_path: str) -> bool:
    """Internal function to perform LSB embedding."""
    try:
        with Image.open(image_path) as img_raw:
            img = img_raw.convert('RGB')
            img_copy = img.copy()
    except FileNotFoundError:
        print(f"Error: Input image file not found: {image_path}")
        return False
    except Exception as e:
        print(f"Error opening or converting image {image_path}: {e}")
        return False
    width, height = img_copy.size
    max_bits = width * height * 3
    bits_to_hide = list(data_to_bits(data_to_hide))
    num_bits_to_hide = len(bits_to_hide)
    print(f"Image dimensions: {width}x{height}")
    print(f"Maximum embeddable bits: {max_bits}")
    print(f"Total bits to hide (incl. headers): {num_bits_to_hide}")
    if num_bits_to_hide > max_bits: print(
        f"Error: Not enough space. Required: {num_bits_to_hide}, Available: {max_bits}"); return False
    pixels = img_copy.load()
    bit_index = 0
    try:
        for y in range(height):
            for x in range(width):
                if bit_index >= num_bits_to_hide: break
                pixel_val = pixels[x, y]
                if not isinstance(pixel_val, tuple) or len(pixel_val) != 3: continue
                r, g, b = pixel_val
                if bit_index < num_bits_to_hide: r = (r & 0xFE) | bits_to_hide[bit_index]; bit_index += 1
                if bit_index < num_bits_to_hide: g = (g & 0xFE) | bits_to_hide[bit_index]; bit_index += 1
                if bit_index < num_bits_to_hide: b = (b & 0xFE) | bits_to_hide[bit_index]; bit_index += 1
                pixels[x, y] = (r, g, b)
            if bit_index >= num_bits_to_hide: break
    except Exception as e:
        print(f"Error during pixel modification: {e}")
        return False
    if bit_index < num_bits_to_hide: print("Error: Failed to embed all bits."); return False
    try:
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir): os.makedirs(output_dir, exist_ok=True)
        img_copy.save(output_path, format='PNG')
        return True
    except Exception as e:
        print(f"Error saving output image to {output_path}: {e}")
        return False


def run_embedding(cover_image_path: str, secret_file_path: str, passphrase: str, output_stego_path: str) -> bool:
    """Handles the complete file embedding workflow."""
    print("\n--- Starting Embedding Process ---")
    try:
        # 1. Read Secret File Content
        if not os.path.isfile(secret_file_path):
            raise FileNotFoundError(f"Secret file '{secret_file_path}' not found or is not a file.")
        with open(secret_file_path, 'rb') as f_in:
            file_content_bytes = f_in.read()
        if not file_content_bytes: print("Warning: Secret file is empty.")

        # 2. Get and Prepare Filename (uses FILENAME_LEN_BYTES config)
        original_filename = os.path.basename(secret_file_path)
        filename_bytes = original_filename.encode('utf-8')
        filename_len = len(filename_bytes)
        if filename_len > (2 ** (FILENAME_LEN_BYTES * 8) - 1):  # Max value for the field size
            raise ValueError(f"Filename too long ({filename_len} bytes > max {2 ** (FILENAME_LEN_BYTES * 8) - 1}).")
        filename_len_bytes_field = filename_len.to_bytes(FILENAME_LEN_BYTES, byteorder='big')
        print(f"Preparing filename: '{original_filename}' ({filename_len} bytes)")

        # 3. Generate Salt & Derive Key (uses SALT_LENGTH_BYTES config, derive_key_kdf func)
        salt = os.urandom(SALT_LENGTH_BYTES)
        print(f"Generated unique salt ({SALT_LENGTH_BYTES} bytes).")
        key = derive_key_kdf(passphrase, salt)  # From steg_tool

        # 4. Encrypt File Content (uses encrypt_message func)
        encrypted_file_data = encrypt_message(key, file_content_bytes)  # From steg_tool
        print(f"File content encrypted ({len(encrypted_file_data)} bytes including nonce/tag).")

        # 5. Prepare Full Payload (uses config values)
        payload_to_embed = salt + filename_len_bytes_field + filename_bytes + encrypted_file_data
        total_payload_len = len(payload_to_embed)
        total_payload_len_bytes_field = total_payload_len.to_bytes(LENGTH_FIELD_BYTES, byteorder='big')
        print(f"Total payload length (excluding header): {total_payload_len} bytes")

        # 6. Prepare Final Data to Hide
        data_to_hide = total_payload_len_bytes_field + payload_to_embed

        # 7. Embed Data using internal LSB function
        success = _embed_data_lsb(cover_image_path, data_to_hide, output_stego_path)

        if success:
            print(f"Successfully embedded data into {output_stego_path}")
            print("--- Embedding Process Completed Successfully ---")
            return True
        else:
            print("--- Embedding Process Failed ---")
            return False

    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False
    except ValueError as e:
        print(f"Error: {e}")
        return False
    except Exception as e:
        print(f"\nAn unexpected error occurred during embedding workflow: {e}")
        return False


def extract_and_save_file(image_path: str, passphrase: str, output_dir: str) -> str | None:
    """
    Handles the complete file extraction workflow.
    Extracts salt, filename, and encrypted file data, derives key, decrypts,
    and saves the file (prefixed with 'decrypted_') to the specified output directory.
    Returns the saved file path on success, None on failure.
    """
    print("\n--- Starting Extraction Process ---")
    if not os.path.isdir(output_dir):
        try:
            print(f"Output directory '{output_dir}' does not exist. Creating it.")
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(f"Error: Could not create output directory '{output_dir}': {e}"); return None

    bit_gen = extract_bits_generator(image_path)
    try:
        def _extract_next_bytes(num_bytes):
            bits = []
            needed_bits = num_bytes * 8
            try:
                for _ in range(needed_bits): bits.append(next(bit_gen))
            except StopIteration:
                raise ValueError(f"Could not extract {needed_bits} bits for {num_bytes} bytes. Image data ended.")
            byte_data = bits_to_bytes(bits)
            if len(byte_data) != num_bytes: raise ValueError(
                f"Extracted data length mismatch. Expected {num_bytes}B, got {len(byte_data)}B.")
            return byte_data

        # 1. Extract Total Payload Length (uses LENGTH_FIELD_BYTES config)
        total_payload_length_bytes = _extract_next_bytes(LENGTH_FIELD_BYTES)
        total_payload_length = int.from_bytes(total_payload_length_bytes, byteorder='big')
        print(f"Expected total payload length (Salt+FilenameInfo+EncryptedData): {total_payload_length} bytes")
        if total_payload_length <= SALT_LENGTH_BYTES + FILENAME_LEN_BYTES: raise ValueError("Payload length invalid.")

        # 2. Extract Salt (uses SALT_LENGTH_BYTES config)
        salt = _extract_next_bytes(SALT_LENGTH_BYTES)
        print(f"Extracted salt ({len(salt)} bytes).")

        # 3. Extract Filename Length (uses FILENAME_LEN_BYTES config)
        filename_len_bytes = _extract_next_bytes(FILENAME_LEN_BYTES)
        filename_len = int.from_bytes(filename_len_bytes, byteorder='big')
        print(f"Expected filename length: {filename_len} bytes.")
        if filename_len <= 0: raise ValueError("Invalid filename length extracted.")

        # 4. Extract Filename
        filename_bytes = _extract_next_bytes(filename_len)
        original_filename = filename_bytes.decode('utf-8', errors='replace')
        safe_filename_base = os.path.basename(original_filename.replace('/', '_').replace('\\', '_'))
        if not safe_filename_base: safe_filename_base = "extracted_file"  # Handle empty names after sanitization

        final_save_filename = f"decrypted_{safe_filename_base}"
        print(f"Extracted original filename: '{original_filename}' (Saving as: '{final_save_filename}')")

        # 5. Calculate and Extract Encrypted File Data
        encrypted_file_data_len = total_payload_length - SALT_LENGTH_BYTES - FILENAME_LEN_BYTES - filename_len
        if encrypted_file_data_len < 0: raise ValueError("Calculated encrypted data length invalid (< 0).")

        encrypted_file_data = b''
        if encrypted_file_data_len == 0:
            print("Warning: Calculated encrypted data length is zero. Extracted file will be empty.")
        else:
            print(f"Calculated encrypted file data length: {encrypted_file_data_len} bytes.")
            encrypted_file_data = _extract_next_bytes(encrypted_file_data_len)
            print(f"Extracted encrypted file data ({len(encrypted_file_data)} bytes).")

        # 6. Derive key (uses derive_key_kdf func)
        key = derive_key_kdf(passphrase, salt)  # From steg_tool

        # 7. Decrypt (uses decrypt_message func)
        decrypted_file_bytes = b''
        if encrypted_file_data_len > 0:  # Only decrypt if there's data
            if len(encrypted_file_data) < NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES:
                raise ValueError("Encrypted data length mismatch, too short for nonce/tag.")
            decrypted_file_bytes = decrypt_message(key, encrypted_file_data)  # From steg_tool
            print("File data decrypted successfully.")
        else:
            print("Skipping decryption for zero-length payload.")

        # 8. Save the decrypted file
        output_file_path = os.path.join(output_dir, final_save_filename)
        print(f"Attempting to save decrypted file to: {output_file_path}")
        try:
            with open(output_file_path, 'wb') as f_out:
                f_out.write(decrypted_file_bytes)
            print(f"Successfully saved decrypted file.")
            return output_file_path
        except IOError as e:
            print(f"Error: Could not write file '{output_file_path}': {e}"); return None

    except (StopIteration, ValueError, UnicodeDecodeError) as e:
        print(f"Error during extraction: {e}"); return None
    except Exception as e:
        print(f"An unexpected extraction error occurred: {e}"); return None


def main_cli():
    parser = argparse.ArgumentParser(
        description="Hide files within images using LSB steganography and AES-GCM encryption.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.epilog = f"""
Configuration loaded from '{CONFIG_FILE}' (defaults used if missing/invalid).
Current Settings: PBKDF2 Iterations={PBKDF2_ITERATIONS}, Salt Bytes={SALT_LENGTH_BYTES}
Use lossless image formats like PNG for output stego-images.
"""

    subparsers = parser.add_subparsers(dest='mode', required=True, help='Choose mode: embed or extract')

    parser_embed = subparsers.add_parser('embed', help='Embed a secret file into a cover image')
    parser_embed.add_argument('-i', '--image', required=True, help='Path to the input cover image')
    parser_embed.add_argument('-s', '--secret-file', required=True, help='Path to the secret file to hide')
    parser_embed.add_argument('-o', '--output', required=True,
                              help='Path to save the output stego-image (e.g., output.png)')

    parser_extract = subparsers.add_parser('extract', help='Extract a hidden file from a stego-image')
    parser_extract.add_argument('-i', '--image', required=True, help='Path to the input stego-image')
    parser_extract.add_argument('-d', '--output-dir', required=True, help='Directory path to save the extracted file')

    try:
        args = parser.parse_args()
        print("\nPassphrase required.")
        while True:
            try:
                passphrase = getpass.getpass("Enter passphrase: ")
                if passphrase:
                    break
                else:
                    print("Passphrase cannot be empty.")
            except (EOFError, KeyboardInterrupt):
                print("\nOperation cancelled during passphrase input. Exiting.")
                sys.exit(1)

        success = False
        if args.mode == 'embed':
            success = run_embedding(
                cover_image_path=args.image,
                secret_file_path=args.secret_file,
                passphrase=passphrase,
                output_stego_path=args.output
            )

        elif args.mode == 'extract':
            saved_path = extract_and_save_file(
                image_path=args.image,
                passphrase=passphrase,
                output_dir=args.output_dir
            )
            success = saved_path is not None

        if not success: sys.exit(1)

    except FileNotFoundError as e:
        print(f"Error: File not found - {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    load_config()
    main_cli()
