# backend/api.py

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from backend.dll_wrapper import encrypt_text, decrypt_text, encrypt_file, decrypt_file
import tempfile
import os

router = APIRouter()

# === TEXT ENCRYPTION ===

class TextCryptoRequest(BaseModel):
    mode: str
    text: str  # plaintext for encrypt, ciphertext for decrypt
    key: str   # hex string
    iv: str    # hex string

@router.post("/encrypt")
def encrypt_text_endpoint(req: TextCryptoRequest):
    try:
        key_bytes = bytes.fromhex(req.key)
        iv_bytes = bytes.fromhex(req.iv)

        key_size = len(key_bytes) * 8

        if key_size not in (128, 192, 256):
            raise HTTPException(status_code=400, detail="Invalid key length. Must be 128, 192, or 256 bits.")

        result = encrypt_text(req.mode, req.text, key_bytes, iv_bytes, key_size)
        return {"ciphertext": result}

    except ValueError as ve:
        print(f"[ENCRYPT] ValueError: {ve}")
        raise HTTPException(status_code=400, detail=f"Invalid hex in key/IV or text: {ve}")

    except Exception as e:
        print(f"[ENCRYPT] Exception: {e}")
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")


@router.post("/decrypt")
def decrypt_text_endpoint(req: TextCryptoRequest):
    from base64 import b64decode

    try:
        key_bytes = bytes.fromhex(req.key)
        iv_bytes = bytes.fromhex(req.iv)
        key_bits = len(key_bytes) * 8

        if key_bits not in (128, 192, 256):
            raise HTTPException(status_code=400, detail="Invalid key length. Must be 128, 192, or 256 bits.")

        try:
            decoded_input = b64decode(req.text)
        except Exception:
            raise HTTPException(status_code=400, detail="Ciphertext is not valid Base64.")

        result = decrypt_text(req.mode, decoded_input, key_bytes, iv_bytes, key_bits)
        return {"plaintext": result}

    except Exception as e:
        print(f"[DECRYPT ERROR] {e}")
        raise HTTPException(status_code=400, detail=str(e))





# === FILE ENCRYPTION ===

@router.post("/encrypt-file")
async def encrypt_file_endpoint(
    mode: str = Form(...),
    key: str = Form(...),
    iv: str = Form(...),
    file: UploadFile = File(...)
):
    try:
        key_bytes = bytes.fromhex(key)
        iv_bytes = bytes.fromhex(iv)
        key_bits = len(key_bytes) * 8

        if key_bits not in (128, 192, 256):
            raise HTTPException(status_code=400, detail="Invalid key size")

        input_data = await file.read()

        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_input.write(input_data)
            temp_input_path = temp_input.name

        temp_output_path = f"{temp_input_path}_enc"

        encrypt_file(mode, temp_input_path, temp_output_path, key_bytes, key_bits, iv_bytes)

        return FileResponse(temp_output_path, media_type="application/octet-stream", filename=f"{file.filename}.enc")

    except Exception as e:
        print(f"[FILE ENCRYPT ERROR] {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/decrypt-file")
def decrypt_uploaded_file(
    mode: str = Form(...),
    key: str = Form(...),
    iv: str = Form(...),
    file: UploadFile = File(...)
):
    print("[FILE DECRYPT] Starting decryption...")
    key_bytes = bytes.fromhex(key)
    key_size = len(key_bytes) * 8
    iv_bytes = bytes.fromhex(iv)
    with tempfile.NamedTemporaryFile(delete=False) as input_tmp:
        input_tmp.write(file.file.read())
        input_path = input_tmp.name

    output_path = input_path + ".dec"

    try:
        decrypt_file(mode, input_path, output_path, key_bytes, key_size, iv_bytes)
        return FileResponse(output_path, filename=file.filename + ".dec")
    finally:
        os.remove(input_path)

@router.get("/generate-key")
def get_random_key(bits: int = 128):
    try:
        from backend.dll_wrapper import generate_key
        return {"key": generate_key(bits)}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/generate-iv")
def get_random_iv():
    try:
        from backend.dll_wrapper import generate_iv
        return {"iv": generate_iv()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
