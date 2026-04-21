# ESP32 Crypto API - COSE Extension

This repository is a fork of the `esp32-crypto-api` project, extended to support the CBOR Object Signing and Encryption (COSE) standard. The primary addition is the `CoseCrypto` component, which enables secure messaging for IoT devices using standardized structures.

## New Features: CoseCrypto Class

The `CoseCrypto` class provides a simplified interface for common COSE operations, utilizing MbedTLS and tinyCBOR for the underlying cryptographic and encoding logic.

* **COSE\_Encrypt0**: Support for authenticated encryption using AES-256-GCM.
    * `encrypt()`: Encrypts plaintext and formats it as a `COSE_Encrypt0` message with random IV generation.
    * `decrypt()`: Validates and decrypts incoming `COSE_Encrypt0` messages.
* **COSE\_Sign1**: Support for digital signatures using ECDSA with the NIST P-256 curve (ES256).
    * `sign()`: Signs a payload and formats it into a `COSE_Sign1` structure.
    * `verify()`: Reconstructs the signature structure to verify the authenticity of a `COSE_Sign1` message.
* **Utility**:
    * `generate_test_keypair()`: Generates mathematically valid P-256 keypairs for testing and development.

## Requirements & Dependencies

This fork maintains the core requirements of the original project while introducing new component dependencies:

* **ESP-IDF**: Developed and tested for the ESP-IDF framework.
* **MbedTLS**: Used for AES-GCM and ECDSA cryptographic operations.
* **tinyCBOR**: Integrated via the `espressif__cbor` managed component for processing COSE structures.

## Original Project

For information regarding the original project's benchmarking goals, core cryptography library comparisons (WolfSSL, Micro-ecc), and initial setup instructions, please refer to the original repository by **bristotgl**.
