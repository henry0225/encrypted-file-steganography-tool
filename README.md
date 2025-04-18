# Encrypted File Steganography Tool

**Version:** 1.0 (As of April 18, 2025)
**Author:** [Henry Xue/henry0225]

## Description

This Python tool provides a command-line interface to encrypt and hide files within lossless images using LSB steganography.

Unlike basic LSB techniques that hide plaintext, this tool enhances security significantly by encrypting the secret file using AES-GCM as well as a key derivation function to protect the user-provided passphrase:
against guessing attacks.

Note that any manipulation of the resulting image will likely corrupt the hidden data.
## Features

* Embeds any file type (binary safe) within the LSBs of a cover image.
* Strong AES-256-GCM encryption for confidentiality and data integrity.
* Robust passphrase protection using PBKDF2-HMAC-SHA256 with configurable iterations.
* Unique salt generated for each embedding operation, preventing rainbow table attacks.
* Extracted files are automatically named `decrypted_<original_filename>`.
* Command-line interface for ease of use in scripting.
* Secure passphrase prompting.
* Configurable cryptographic parameters via `config.ini`.

## Requirements

* Python 3.7+
* Required Python libraries:
    * `Pillow`
    * `cryptography`

## Installation
1.  Clone this repository or download the source files into a single directory.
2.  Install the required libraries:
    ```bash
    pip install Pillow cryptography
    ```
## Usage
Embedding a File:
```bash
python steg.py embed -i <cover_image_path> -s <secret_file_path> -o <output_stego_image_path>
```
You will then be prompted for a passphrase that will be used for decryption.

Arguments:

-i, --image: (Required) Path to the input cover image. Must be a lossless format like PNG.

-s, --secret-file: (Required) Path to the file you want to hide (e.g., document.pdf, archive.zip).

-o, --output: (Required) Path where the output stego-image will be saved. Use a lossless format like PNG.

Extracting a File
```bash
python steg.py extract -i <stego_image_path> -d <output_directory_path>
```
You will then be prompted for the passphrase.

Arguments:

-i, --image: (Required) Path to the input stego-image (e.g., stego_image.png).

-d, --output-dir: (Required) Path to the directory where the extracted file should be saved. The directory will be created if it doesn't exist.

## Configuration

The tool uses a `config.ini` file in the same directory to set cryptographic parameters. If the file is missing or contains errors, default values will be used.

**`config.ini` Example:**

```ini
[Crypto]
# Iterations for PBKDF2 - higher is slower but more secure
PBKDF2_ITERATIONS = 600000
# Key length for AES (32 bytes = AES-256)
KEY_LENGTH_BYTES = 32
# Salt length for PBKDF2 (16 bytes recommended)
SALT_LENGTH_BYTES = 16

[Steganography]
# Bytes used to store the total length of the payload
LENGTH_FIELD_BYTES = 4
# Bytes used to store the length of the filename (1 byte = max 255 chars)
FILENAME_LEN_BYTES = 1
```
## License
This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.