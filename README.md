# Adaptive Post-Quantum Secure Communication Framework v2.0 (Demo)

This project demonstrates an **adaptive post-quantum secure communication framework** with:

- **Real-time crypto visualization** (Phases 1–11)
- **Adaptive ML mode selection** (Classical / PQC / Hybrid / Adaptive)
- **ECDHE + ML-KEM (Kyber) handshake simulation**
- **HKDF key derivation**
- **Hybrid composition** (XOR + redundant secure + HKDF)
- **Attack simulation** (HNDL / Replay / MITM / Downgrade)
- **Key ratcheting** (forward secrecy)
- **Phase tracker**
- All concepts explained in the UI

## What’s new: Real file encryption/decryption (Phase 12–14)

After Phase 11 completes, the UI enables a **real file encryption demo**:

1. Upload a file (`.txt`, `.pdf`, `.docx`, `.jpg`, `.png`, max 5MB)
2. **Encrypt** using **AES-256-GCM** with the **HKDF-derived session key `K_enc`**
3. Download a `.pqc` file formatted as:

   - `[JSON_HEADER 256B][NONCE 12B][CIPHERTEXT][HMAC 32B]`

4. **Decrypt & verify** integrity (HMAC verification + AES-GCM authenticated decrypt)

## Demo / Professor flow

1. Set parameters → click **Start Secure Communication** and watch all **11 phases**
2. Upload `demo-files/resume.pdf` or `demo-files/photo.jpg`
3. Click **Encrypt with Session Key** → download `*.pqc`
4. Run the encrypted-file attack outcomes (hybrid resilience)
5. Click **Decrypt & Verify** → original restored and verified

## Demo assets

Sample files are included in `demo-files/`:

- `resume.pdf`
- `photo.jpg`
- `secret.txt`
- `document.docx`

## Requirements

Backend:

- Python 3.x
- `cryptography` (for AES-GCM)
- `Flask`
- `scikit-learn` (optional: used by Adaptive mode; falls back if unavailable)

Install:

```bash
pip install -r requirements.txt
```

## How to run (Windows / PowerShell)

From the project directory:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Then open:

- http://127.0.0.1:5000

## API Endpoints

- `POST /simulate`  
  Runs the 11-phase framework and streams logs via SSE.

- `POST /upload` (Phase 12)  
  Upload a file for the completed session.

- `POST /encrypt` (Phase 13)  
  Encrypt uploaded file with AES-256-GCM using HKDF-derived session key `K_enc`.

- `POST /decrypt` (Phase 14)  
  Verify HMAC and decrypt; restores original file.

- `GET /download/encrypted/<encrypted_id>`
- `GET /download/decrypted/<decrypted_id>`

## Security / Demo note

This framework is an **educational simulation** for the cryptographic protocol phases, while the **file encryption layer is real** using AES-GCM and integrity verification.

---

2-minute professor script is in `PROFESSOR_DEMO_SCRIPT.md`.

