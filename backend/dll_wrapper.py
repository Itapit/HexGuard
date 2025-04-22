# backend/dll_wrapper.py

import ctypes
import os
import base64

dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../build/bin/debug/aes.dll"))
aes = ctypes.CDLL(dll_path)

# === Function Signatures ===

# Key & IV generation
aes.create_key.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
aes.create_iv.argtypes = [ctypes.POINTER(ctypes.c_uint8)]

# Text encryption/decryption
aes.encrypt_text.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8)
]

aes.decrypt_text.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8)
]

# File encryption/decryption
aes.encrypt_file.argtypes = [
    ctypes.c_char_p,                         # mode
    ctypes.c_char_p,                         # input_file_path
    ctypes.c_char_p,                         # output_file_path
    ctypes.POINTER(ctypes.c_uint8),          # key
    ctypes.c_size_t,                         # key_size_bits
    ctypes.POINTER(ctypes.c_uint8)           # iv
]

aes.decrypt_file.argtypes = [
    ctypes.c_char_p,                         # mode
    ctypes.c_char_p,                         # input_file_path
    ctypes.c_char_p,                         # output_file_path
    ctypes.POINTER(ctypes.c_uint8),          # key
    ctypes.c_size_t,                         # key_size (IN BITS!)
    ctypes.POINTER(ctypes.c_uint8)           # iv
]

# === Wrapper Functions ===

def encrypt_text(mode, input_text, key: bytes, iv: bytes, key_bits: int) -> str:
    output_buf = ctypes.create_string_buffer(len(input_text.encode()) * 4)  # generous buffer
    output_len = ctypes.c_size_t()

    aes.encrypt_text(
        mode.encode('utf-8'),
        input_text.encode('utf-8'),
        output_buf,
        ctypes.byref(output_len),
        (ctypes.c_uint8 * len(key)).from_buffer_copy(key),
        key_bits,
        (ctypes.c_uint8 * len(iv)).from_buffer_copy(iv),
    )

    return base64.b64encode(output_buf.raw[:output_len.value]).decode('utf-8')

def decrypt_text(mode, input_bytes: bytes, key: bytes, iv: bytes, key_bits: int) -> str:
    input_len = len(input_bytes)
    output_buf = ctypes.create_string_buffer(input_len * 4)

    aes.decrypt_text(
        mode.encode('utf-8'),
        input_bytes,
        input_len,
        output_buf,
        (ctypes.c_uint8 * len(key)).from_buffer_copy(key),
        key_bits,
        (ctypes.c_uint8 * len(iv)).from_buffer_copy(iv),
    )

    try:
        return output_buf.value.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Decrypted result is not valid UTF-8 text")



def encrypt_file(mode: str, input_path: str, output_path: str, key: bytes, key_bits: int, iv: bytes):
    aes.encrypt_file(
        mode.encode('utf-8'),
        input_path.encode('utf-8'),
        output_path.encode('utf-8'),
        (ctypes.c_uint8 * len(key)).from_buffer_copy(key),
        key_bits,
        (ctypes.c_uint8 * len(iv)).from_buffer_copy(iv),
    )

def decrypt_file(mode: str, input_path: str, output_path: str, key: bytes, key_bits: int, iv: bytes):
    aes.decrypt_file(
        mode.encode('utf-8'),
        input_path.encode('utf-8'),
        output_path.encode('utf-8'),
        (ctypes.c_uint8 * len(key)).from_buffer_copy(key),
        key_bits,
        (ctypes.c_uint8 * len(iv)).from_buffer_copy(iv),
    )


def generate_key(bits: int = 128) -> str:
    if bits not in (128, 192, 256):
        raise ValueError("Key size must be 128, 192, or 256 bits.")

    byte_length = bits // 8
    buf = (ctypes.c_uint8 * byte_length)()
    aes.create_key(buf, bits)  # bits, not bytes
    return ''.join(f"{b:02x}" for b in buf)

def generate_iv() -> str:
    buf = (ctypes.c_uint8 * 16)()
    aes.create_iv(buf)
    return ''.join(f"{b:02x}" for b in buf)
