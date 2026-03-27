"""
app.py — Flask Web Application

Serves the frontend and provides a Server-Sent Events (SSE) endpoint
that streams real-time cryptographic logs to the browser.

SSE (Server-Sent Events): A simple HTTP streaming protocol where the
server keeps a connection open and pushes data as 'data: ...\n\n' lines.
"""

import hashlib
import hmac
import json
import os
import secrets
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from crypto import run_framework

app = Flask(__name__)

MAX_FILE_SIZE = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.docx', '.jpg', '.png'}

# Demo in-memory state (production would use Redis/db)
SESSION_KEYS: Dict[str, Dict[str, bytes]] = {}
UPLOADED_FILES: Dict[str, Dict] = {}
ENCRYPTED_FILES: Dict[str, Dict] = {}
DECRYPTED_FILES: Dict[str, Dict] = {}


def _ext(filename: str) -> str:
    return os.path.splitext(filename.lower())[1]


def _json_header(metadata: dict) -> bytes:
    header_json = json.dumps(metadata, separators=(',', ':')).encode('utf-8')
    if len(header_json) > 256:
        raise ValueError('Metadata header exceeds 256 bytes.')
    return header_json.ljust(256, b' ')


def _build_attack_demo(mode: str) -> list:
    mode_lower = (mode or '').lower()
    quantum_classical = 'SAFE' if mode_lower in ('hybrid', 'pqc') else 'VULNERABLE'
    pqc_vuln = 'SAFE' if mode_lower in ('hybrid', 'classical') else 'VULNERABLE'
    return [
        {
            'name': 'Quantum Attack on Classical Keys',
            'status': quantum_classical,
            'message': (
                'Still secure - ML-KEM component protects K_enc.'
                if quantum_classical == 'SAFE'
                else 'Decryption successful - vulnerable!'
            ),
        },
        {
            'name': 'PQC Vulnerability',
            'status': pqc_vuln,
            'message': (
                'Still secure - ECDHE backup protects K_enc.'
                if pqc_vuln == 'SAFE'
                else 'Vulnerable - PQC-only session can be broken.'
            ),
        },
        {
            'name': 'Key Compromise',
            'status': 'SAFE',
            'message': 'Forward secrecy: ratcheted keys protect future files.',
        },
    ]


@app.route('/')
def index():
    """Serve the main dashboard page."""
    return render_template('index.html')


@app.route('/simulate', methods=['POST'])
def simulate():
    """
    POST /simulate
    Accepts JSON body with session parameters.
    Returns an SSE stream of log events followed by a final results event.
    """
    data = request.get_json(force=True)

    mode             = data.get('mode',             'Hybrid')
    latency_ms       = float(data.get('latency_ms',       50))
    bandwidth_kbps   = float(data.get('bandwidth_kbps', 5000))
    cpu_power_score  = float(data.get('cpu_power_score', 0.8))
    message_size_kb  = float(data.get('message_size_kb',  10))
    security_level   = int(data.get('security_level',      4))
    hndl_risk        = float(data.get('hndl_risk',        0.7))

    def generate():
        """
        Generator that runs the crypto framework and yields
        SSE-formatted strings for each event.
        """
        try:
            selected_mode = mode
            for event in run_framework(
                mode            = mode,
                latency_ms      = latency_ms,
                bandwidth_kbps  = bandwidth_kbps,
                cpu_power_score = cpu_power_score,
                message_size_kb = message_size_kb,
                security_level  = security_level,
                hndl_risk       = hndl_risk,
            ):
                # Keep session keying material server-side for real file encryption demo.
                if event.get('type') == 'results':
                    payload = event.get('payload', {})
                    internal_keys = payload.pop('internal_keys', {})
                    session_id = payload.get('session_id')
                    selected_mode = payload.get('selected_mode', selected_mode)
                    if session_id and internal_keys:
                        SESSION_KEYS[session_id] = {
                            'k_enc': bytes.fromhex(internal_keys['k_enc_hex']),
                            'k_mac': bytes.fromhex(internal_keys['k_mac_hex']),
                            'mode': selected_mode,
                        }

                # SSE format: "data: <json>\n\n"
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as exc:
            error_event = {
                'type'   : 'log',
                'level'  : 'ERROR',
                'message': f'[Fatal] Framework error: {exc}',
            }
            yield f"data: {json.dumps(error_event)}\n\n"

        # Signal stream end
        yield "data: {\"type\": \"end\"}\n\n"

    headers = {
        'Content-Type'      : 'text/event-stream',
        'Cache-Control'     : 'no-cache',
        'X-Accel-Buffering' : 'no',     # Disable nginx buffering in production
        'Connection'        : 'keep-alive',
    }

    return Response(
        stream_with_context(generate()),
        headers=headers
    )


@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded = request.files.get('file')
    session_id = request.form.get('session_id', '')
    if not uploaded or not uploaded.filename:
        return jsonify({'error': 'No file provided.'}), 400
    if session_id not in SESSION_KEYS:
        return jsonify({'error': 'Invalid or expired session. Run simulation first.'}), 400

    ext = _ext(uploaded.filename)
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({'error': 'Unsupported file type.'}), 400

    data = uploaded.read()
    if len(data) > MAX_FILE_SIZE:
        return jsonify({'error': 'File exceeds 5MB limit.'}), 400

    upload_id = secrets.token_hex(8)
    UPLOADED_FILES[upload_id] = {
        'session_id': session_id,
        'filename': uploaded.filename,
        'size': len(data),
        'mime': uploaded.mimetype or 'application/octet-stream',
        'content': data,
    }
    return jsonify({
        'upload_id': upload_id,
        'name': uploaded.filename,
        'size': len(data),
        'type': uploaded.mimetype or 'application/octet-stream',
    })


@app.route('/encrypt', methods=['POST'])
def encrypt_uploaded():
    body = request.get_json(force=True)
    session_id = body.get('session_id', '')
    upload_id = body.get('upload_id', '')
    if session_id not in SESSION_KEYS:
        return jsonify({'error': 'Session not found.'}), 400
    uploaded = UPLOADED_FILES.get(upload_id)
    if not uploaded or uploaded['session_id'] != session_id:
        return jsonify({'error': 'Uploaded file not found for this session.'}), 400

    keys = SESSION_KEYS[session_id]
    k_enc = keys['k_enc']
    k_mac = keys['k_mac']
    plaintext = uploaded['content']
    nonce = os.urandom(12)
    aesgcm = AESGCM(k_enc)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    key_id = f"session_{session_id[:6]}"
    header_meta = {
        'version': '1.0',
        'mode': keys['mode'].lower(),
        'key_id': key_id,
        'nonce_size': 12,
        'cipher': 'AES-256-GCM',
    }
    header = _json_header(header_meta)
    mac = hmac.new(k_mac, header + nonce + ciphertext, hashlib.sha256).digest()
    blob = header + nonce + ciphertext + mac

    encrypted_id = secrets.token_hex(8)
    ENCRYPTED_FILES[encrypted_id] = {
        'session_id': session_id,
        'filename': f"{uploaded['filename']}.pqc",
        'blob': blob,
        'header': header_meta,
        'nonce': nonce,
        'ciphertext': ciphertext,
        'hmac': mac,
        'original_name': uploaded['filename'],
        'original_size': len(plaintext),
        'encrypted_size': len(blob),
        'original_hash': hashlib.sha256(plaintext).hexdigest(),
    }
    return jsonify({
        'encrypted_id': encrypted_id,
        'message': 'Encrypted with AES-256-GCM using HKDF-derived K_enc',
        'download_url': f'/download/encrypted/{encrypted_id}',
        'comparison': {
            'original': len(plaintext),
            'encrypted': len(blob),
            'overhead': len(blob) - len(plaintext),
        },
        'file_attack_results': _build_attack_demo(keys['mode']),
    })


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    body = request.get_json(force=True)
    session_id = body.get('session_id', '')
    encrypted_id = body.get('encrypted_id', '')
    if session_id not in SESSION_KEYS:
        return jsonify({'error': 'Session not found.'}), 400
    enc = ENCRYPTED_FILES.get(encrypted_id)
    if not enc or enc['session_id'] != session_id:
        return jsonify({'error': 'Encrypted file not found for this session.'}), 400

    keys = SESSION_KEYS[session_id]
    blob = enc['blob']
    header = blob[:256]
    nonce = blob[256:268]
    mac_received = blob[-32:]
    ciphertext = blob[268:-32]
    mac_calc = hmac.new(keys['k_mac'], header + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_calc):
        return jsonify({'error': 'HMAC verification failed.'}), 400

    plaintext = AESGCM(keys['k_enc']).decrypt(nonce, ciphertext, None)
    decrypted_id = secrets.token_hex(8)
    DECRYPTED_FILES[decrypted_id] = {
        'session_id': session_id,
        'filename': enc['original_name'],
        'content': plaintext,
    }
    restored_hash = hashlib.sha256(plaintext).hexdigest()
    return jsonify({
        'decrypted_id': decrypted_id,
        'download_url': f'/download/decrypted/{decrypted_id}',
        'restored': restored_hash == enc['original_hash'],
        'original_hash': enc['original_hash'],
        'restored_hash': restored_hash,
        'message': 'Original file restored and verified.',
    })


@app.route('/download/encrypted/<encrypted_id>', methods=['GET'])
def download_encrypted(encrypted_id):
    from flask import send_file
    import io
    item = ENCRYPTED_FILES.get(encrypted_id)
    if not item:
        return jsonify({'error': 'Encrypted file not found.'}), 404
    return send_file(
        io.BytesIO(item['blob']),
        as_attachment=True,
        download_name=item['filename'],
        mimetype='application/octet-stream',
    )


@app.route('/download/decrypted/<decrypted_id>', methods=['GET'])
def download_decrypted(decrypted_id):
    from flask import send_file
    import io
    item = DECRYPTED_FILES.get(decrypted_id)
    if not item:
        return jsonify({'error': 'Decrypted file not found.'}), 404
    return send_file(
        io.BytesIO(item['content']),
        as_attachment=True,
        download_name=item['filename'],
        mimetype='application/octet-stream',
    )


if __name__ == '__main__':
    app.run(debug=True, threaded=True, host='0.0.0.0', port=5000)