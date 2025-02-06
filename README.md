# HexGuard - AES Encryption Library

## Overview
HexGuard is an **AES encryption library** implemented in **C**. This project is part of my **13th grade final project** for the academic year **2024-2025**. The goal is to implement a robust AES encryption system while exploring advanced cryptographic techniques.

## Features
- **AES Encryption & Decryption**:
  - Supports **AES-128, AES-192, and AES-256** key sizes.
  - Implements **ECB, CBC, and CFB** modes of operation.
  - Uses **PKCS#7 padding** for encryption.

- **Key & IV Management**:
  - Generates random **AES keys**.
  - Creates **initialization vectors (IVs)** for CBC and CFB modes.

- **File & Text Encryption**:
  - Encrypts and decrypts **text strings**.
  - Encrypts and decrypts **files** in binary mode.
  - Performs **integrity checks** after decryption.

- **Testing Framework**:
  - Includes **unit tests** for encryption and decryption.
  - Validates correct key expansion and AES transformations.

---

## Installation & Setup
### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/hexguard.git
cd hexguard
```

### 2. Build the Project Using CMake
Ensure you have **CMake** installed:
```bash
cmake -B build
cd build
make
```
This will generate the `test_aes` executable.

### 3. Run Tests
```bash
./bin/test_aes
```
The test suite will verify encryption and decryption functionality.

---

## Usage
> **Note:** As of now, the files and text used in encryption and decryption are hardcoded in the source code. This will be changed in the future.

---

## File Structure
```
├── include/
│   ├── aes.h        # AES function declarations
├── lib/
│   ├── aes.c        # AES implementation
├── tests/
│   ├── test_aes.c   # Test cases for AES functions
├── CMakeLists.txt   # CMake build configuration
├── README.md        # Project documentation
```

---

## Roadmap & Future Work
- Implement additional AES **modes of operation** (e.g., **OFB, CTR**).
- Optimize **key expansion** for better efficiency.
- Improve **error handling** for encryption functions.
- Using **graph theory** to add additional cryptographic enhancements to the key expansion.
- Adding a **GUI** that will be written in **Java**, utilizing the **C code as a DLL**.

---

## Contact
For any questions or contributions, feel free to reach out!

