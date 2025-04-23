# HexGuard - AES Encryption Library

## Overview
HexGuard is an **AES encryption library** implemented in **C**. This project is part of my **13th grade final project** for the academic year **2024-2025**. The goal is to implement a robust AES encryption system while exploring advanced cryptographic techniques.

## Features
- **AES Encryption & Decryption**
  - Supports AES-128, AES-192, and AES-256 key sizes.
  - Implements ECB, CBC, and CFB modes of operation.
  - Uses **PKCS#7 padding**.

- **Key & IV Handling**
  - Random **key generation** and **IV creation**.
  - (Used an external lib didn't impliment my self the generation)

- **Text & File Support**
  - Encrypts/decrypts **text** and **files** (binary-safe).

- **DLL & EXE Build Modes**
  - Build as a **Windows DLL** or a **testable executable**.

- **Python Frontend**
  - Simple encryption GUI using HTML, CSS, JS.
  - Powered by FastApi

- **Testing Framework**
  - Includes unit tests for encryption and decryption.
  - Validates correct key expansion and AES transformations.


## Technologies Used
- **C** – Core AES encryption implementation.
- **Python** – Used for backend API and DLL interaction with FastAPI.
- **HTML / CSS / JavaScript** – Simple web interface for user interaction.
- **CMake** – Build system used to compile the AES code into a DLL or EXE.
- **FastAPI** – Framework powering the Python backend.
- **ctypes** – Used for calling C functions from Python.


---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Itapit/hexguard.git
cd hexguard
```

### 2. Set Up Python Environment (Frontend)
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # On Windows
pip install fastapi uvicorn python-multipart
```

Then run:
```bash
uvicorn backend.main:app --reload
```
This serves the frontend at `http://127.0.0.1:8000`.

### 3. Build C Components Using CMake

#### Option A: Build DLL (for integration)
```bash
cmake -S . -B build -DBUILD_DLL=ON
cmake --build build
```
Output: `build/bin/Debug/aes.dll`

#### Option B: Build and Run Tests
```bash
cmake -S . -B build -DBUILD_DLL=OFF
cmake --build build
./build/bin/Debug/test_aes.exe
```
Output: `build/bin/Debug/test_aes.exe`

---

## File Structure
```
hexguard/
├── backend/
│   ├── api.py              # FastAPI routes
│   ├── dll_wrapper.py      # Interface to AES DLL
│   └── main.py             # FastAPI app runner
│
├── build/
│   └── bin/
│       └── Debug/
│           ├── aes.dll        # DLL output
│           └── test_aes.exe   # Executable with the unit testing
│
├── frontend/
│   ├── index.html          # UI layout
│   ├── script.js           # Frontend logic
│   └── style.css           # UI styling
│
├── include/
│   └── aes.h               # AES header file
│
├── lib/
│   └── aes.c               # AES C implementation
│
├── tests/
│   └── test_aes.c          # Unit tests
│
├── CMakeLists.txt
│
└── README.md
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
For questions or contributions, reach out at ItamarDavid90@gmail.com.
