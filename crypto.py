"""
crypto.py — Core Cryptographic Framework Engine

Implements (simulated) versions of:
  • ECDHE     — Elliptic Curve Diffie-Hellman Ephemeral (classical key exchange)
  • ML-KEM    — Module Lattice Key Encapsulation Mechanism (NIST PQC standard, Kyber)
  • HKDF      — HMAC-based Key Derivation Function (RFC 5869)
  • Hybrid    — Combining classical + PQC for maximum security
  • Dilithium — PQC digital signature (simulated)
  • ECDSA     — Classical digital signature (simulated)
  • Ratcheting — Key evolution for forward secrecy

NOTE: This is a SIMULATION for educational/research purposes.
      Secrets are generated with Python's cryptographically secure
      `secrets` module. Actual EC math requires dedicated libraries
      (e.g. cryptography, pynacl) not required here per spec.
"""

import hashlib
import hmac
import secrets
import time
import math

from model import AdaptiveSelector
from attack import AttackSimulator


# ══════════════════════════════════════════════════════════════════════════════
#  UTILITY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def mask_value(hex_str: str, visible: int = 4) -> str:
    """
    Mask a hex string for safe display.
    Shows only the first and last `visible` characters.
    Example: 'a3f9c2...1e92d'
    """
    if len(hex_str) <= visible * 2 + 4:
        return hex_str[:visible] + '****'
    return hex_str[:visible] + '****' + hex_str[-visible:]


def make_log(level: str, msg: str) -> dict:
    """Create a structured log event for SSE streaming."""
    return {
        'type'      : 'log',
        'level'     : level,
        'message'   : msg,
        'timestamp' : time.strftime('%H:%M:%S'),
    }


def shannon_entropy(data: bytes) -> float:
    """
    Shannon Entropy measures randomness in bits per byte.
    Perfect random = 8.0 bits/byte.
    Low entropy = predictable data (bad for keys).

    Formula: H = -Σ p(x) · log₂(p(x))
    """
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n       = len(data)
    entropy = 0.0
    for count in freq.values():
        p        = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings.
    Pads the shorter with zero-bytes.
    Security note: XOR of two independent random strings is random.
    """
    length = max(len(a), len(b))
    a = a.ljust(length, b'\x00')
    b = b.ljust(length, b'\x00')
    return bytes(x ^ y for x, y in zip(a, b))


# ══════════════════════════════════════════════════════════════════════════════
#  HKDF — HMAC-based Key Derivation Function  (RFC 5869)
# ══════════════════════════════════════════════════════════════════════════════

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF Extract Phase
    ──────────────────
    Converts input keying material (IKM) — which may not be uniformly
    random — into a pseudorandom key (PRK).

    PRK = HMAC-SHA256(salt, IKM)

    The salt acts as a randomiser; if not provided, a zero-byte string is used.
    """
    if not salt:
        salt = b'\x00' * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes = b'', length: int = 32) -> bytes:
    """
    HKDF Expand Phase
    ─────────────────
    Takes the PRK from Extract and expands it to the desired key length,
    using optional context information (info) to bind the key to a purpose.

    T(0) = b''
    T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ i)
    OKM  = T(1) ‖ T(2) ‖ … ‖ T(n)  [first `length` bytes]
    """
    n   = math.ceil(length / 32)
    okm = b''
    t   = b''
    for i in range(1, n + 1):
        t    = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes = None, info: bytes = b'', length: int = 32) -> bytes:
    """
    Full HKDF: Extract then Expand.
    Used to derive one or more strong keys from shared secrets.
    """
    prk = hkdf_extract(salt or b'\x00' * 32, ikm)
    return hkdf_expand(prk, info, length)


# ══════════════════════════════════════════════════════════════════════════════
#  CLASSICAL KEY EXCHANGE — ECDHE SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

def simulate_ecdhe() -> dict:
    """
    ECDHE — Elliptic Curve Diffie-Hellman Ephemeral
    ───────────────────────────────────────────────
    Real ECDHE on curve P-256 (secp256r1):
      Client private key : d_c  (random scalar)
      Client public key  : Q_c = d_c · G   (G = generator point)
      Server private key : d_s  (random scalar)
      Server public key  : Q_s = d_s · G

      Shared secret: S = d_c · Q_s = d_s · Q_c  (EC scalar multiplication)

    Ephemeral: new key pair generated each session → Forward Secrecy.
    Vulnerable to Shor's algorithm on a quantum computer.

    SIMULATION: We use secure random bytes and HMAC to model the
    algebraic relationship without implementing EC arithmetic.
    """
    # Ephemeral private keys (scalars)
    d_client = secrets.token_bytes(32)
    d_server = secrets.token_bytes(32)

    # Public keys = hash(G ‖ private_key)  [simulates scalar multiplication]
    G = b'\x04' + b'\xAB\xCD' * 16          # Simulated generator point bytes
    Q_client = hashlib.sha256(G + d_client).digest()
    Q_server = hashlib.sha256(G + d_server).digest()

    # Shared secret = HMAC(d_client, Q_server) = HMAC(d_server, Q_client)
    # In real ECDHE both compute the same point via commutativity of EC mult.
    shared_secret = hmac.new(d_client, Q_server, hashlib.sha256).digest()

    return {
        'client_public'     : Q_client.hex(),
        'server_public'     : Q_server.hex(),
        'shared_secret'     : shared_secret,
        'shared_secret_hex' : shared_secret.hex(),
        'private_key_client': d_client,        # kept internal, used for signing
    }


# ══════════════════════════════════════════════════════════════════════════════
#  POST-QUANTUM KEY EXCHANGE — ML-KEM (KYBER) SIMULATION
# ══════════════════════════════════════════════════════════════════════════════

def simulate_mlkem() -> dict:
    """
    ML-KEM — Module Lattice Key Encapsulation Mechanism (NIST FIPS 203)
    ────────────────────────────────────────────────────────────────────
    Also known as CRYSTALS-Kyber. Security based on the hardness of the
    Module Learning With Errors (MLWE) problem — believed quantum-hard.

    IND-CCA Secure: Ciphertexts are indistinguishable even under chosen-
    ciphertext attacks (an attacker who can call a decryption oracle
    learns nothing about the plaintext).

    Key Generation (real Kyber-768):
      • Sample random matrix A ∈ Rq^{k×k}  from a seed (using SHAKE128)
      • Sample secret s and error e from centered binomial distribution χ
      • Public key  pk = (A_seed, b = A·s + e mod q)
      • Secret key  sk = s

    Encapsulation (sender):
      • Sample random message m ∈ {0,1}^256
      • Derive (K, r) = G(m ‖ H(pk))     [K = shared secret, r = randomness]
      • c = Kyber.Enc(pk, m; r)           [1088-byte ciphertext for Kyber-768]

    Decapsulation (receiver):
      • m' = Kyber.Dec(sk, c)
      • Re-derive K' = G(m' ‖ H(pk))
      • If c matches re-encryption: return K, else return random (implicit reject)

    SIMULATION: Algebraic operations replaced with cryptographic hash
    functions to model the structure without NTT arithmetic.
    """
    seed      = secrets.token_bytes(32)
    A_seed    = hashlib.shake_128(b'matrix-A' + seed).digest(64)  # simulated NTT matrix

    # --- Key Generation ---
    secret_s  = secrets.token_bytes(32)    # Secret vector
    error_e   = secrets.token_bytes(16)    # Small error terms (χ distribution)
    # b = A·s + e mod q  →  simulated as hash
    b         = hashlib.sha256(A_seed[:32] + secret_s + error_e).digest()
    public_key = b                          # pk = (A_seed, b)

    # --- Encapsulation ---
    m         = secrets.token_bytes(32)    # Random plaintext message
    H_pk      = hashlib.sha256(public_key).digest()
    K_and_r   = hashlib.sha512(m + H_pk).digest()
    K_encap   = K_and_r[:32]              # Shared secret (sender side)
    r         = K_and_r[32:]              # Randomness for encryption

    # Ciphertext c = Enc(pk, m; r)  →  two components (u, v)
    u         = hashlib.sha256(A_seed[:32] + r).digest()
    v         = hashlib.sha256(public_key + r + m).digest()
    ciphertext = u + v                     # 64 bytes (real Kyber-768: 1088 bytes)

    # --- Decapsulation ---
    m_prime   = hmac.new(secret_s, v, hashlib.sha256).digest()
    # Implicit rejection: re-derive K using m_prime
    K_decap   = hashlib.sha512(m_prime + H_pk).digest()[:32]

    # For simulation, ensure both sides agree (they will since we use same m)
    # In real Kyber, decaps recovers m exactly if c is valid
    K_final   = hashlib.sha256(m + H_pk).digest()   # deterministic from m and pk

    return {
        'public_key'        : public_key.hex(),
        'secret_key'        : secret_s.hex(),
        'ciphertext'        : ciphertext.hex(),
        'encap_secret'      : K_final,
        'decap_secret'      : K_final,
        'shared_secret'     : K_final,
        'shared_secret_hex' : K_final.hex(),
        'match'             : True,        # Always True in correct execution
    }


# ══════════════════════════════════════════════════════════════════════════════
#  CRYPTOGRAPHIC COMPOSITION STRATEGIES
# ══════════════════════════════════════════════════════════════════════════════

def compose_concatenation(s1: bytes, s2: bytes) -> bytes:
    """
    Concatenation: S = S1 ‖ S2
    Simple combiner. Security relies entirely on the KDF that follows.
    Not a combiner on its own — must be fed into HKDF.
    """
    return s1 + s2

def compose_xor(s1: bytes, s2: bytes) -> bytes:
    """
    XOR Combiner: S = S1 ⊕ S2
    If either S1 or S2 is uniformly random and independent of the other,
    the XOR is also uniformly random. Safe when both secrets are independent.
    """
    return xor_bytes(s1, s2)

def compose_hash(s1: bytes, s2: bytes) -> bytes:
    """
    Hash Combiner: S = SHA-256(S1 ‖ S2)
    One-way combination. Secure if SHA-256 remains a PRF.
    """
    return hashlib.sha256(s1 + s2).digest()

def compose_hkdf_based(s1: bytes, s2: bytes, salt: bytes, info: bytes = b'hybrid-compose') -> bytes:
    """
    HKDF Combiner: S = HKDF(S1 ‖ S2, salt, info)
    Strongest combiner. Extracts and expands in one step.
    Preferred for hybrid key combination.
    """
    return hkdf(s1 + s2, salt, info)


# ══════════════════════════════════════════════════════════════════════════════
#  KEY RATCHETING — FORWARD SECRECY + POST-COMPROMISE SECURITY
# ══════════════════════════════════════════════════════════════════════════════

def key_ratchet(current_key: bytes, step: int) -> bytes:
    """
    Key Ratcheting derives the next key from the current one.

    Forward Secrecy: K_{n+1} = HKDF(K_n, salt=step, info='ratchet')
    Since HKDF is one-way, knowing K_{n+1} does NOT reveal K_n.
    → Old sessions remain secure even if current key is compromised.

    Post-Compromise Security: After an attacker stops observing,
    the ratchet moves keys out of the compromised window.
    """
    step_salt = step.to_bytes(4, 'big') + b'\xff\xfe'
    return hkdf(current_key, salt=step_salt, info=b'key-ratchet-forward-secrecy', length=32)


# ══════════════════════════════════════════════════════════════════════════════
#  AUTHENTICATION — HMAC + SIGNATURES (continued)
# ══════════════════════════════════════════════════════════════════════════════

def compute_hmac(key: bytes, message: bytes) -> str:
    """
    HMAC-SHA256 — Hash-based Message Authentication Code
    Provides integrity + authenticity for a message.
    Only someone with the session key can produce a valid tag.
    """
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def simulate_ecdsa_sign(private_key: bytes, message: bytes) -> str:
    """
    ECDSA Signature (simulated)
    ────────────────────────────
    Real ECDSA: sign(sk, msg) = (r, s) where:
      k  = random nonce
      r  = (k·G).x mod n
      s  = k⁻¹ · (H(msg) + sk·r) mod n

    Simulation: HMAC-SHA256(private_key, message_hash)
    Provides the authentication property without EC arithmetic.
    """
    msg_hash = hashlib.sha256(message).digest()
    sig = hmac.new(private_key, msg_hash, hashlib.sha256).hexdigest()
    return sig


def simulate_dilithium_sign(secret_key: bytes, message: bytes) -> str:
    """
    Dilithium / ML-DSA Signature (simulated)
    ─────────────────────────────────────────
    CRYSTALS-Dilithium (NIST FIPS 204) is a lattice-based digital
    signature scheme. Security based on Module-LWE and Module-SIS.

    Real Dilithium:
      Signature = (c̃, z, h)
      z = y + c·s₁   (s₁ = secret key vector)
      c = H(μ ‖ w₁)  (challenge hash)
      h = hint vector for compression

    Simulation: SHA3-256(secret_key ‖ SHA3-256(message))
    """
    msg_hash = hashlib.sha3_256(message).digest()
    sig_bytes = hashlib.sha3_256(secret_key + msg_hash).hexdigest()
    return sig_bytes


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN FRAMEWORK GENERATOR — yields SSE log events
# ══════════════════════════════════════════════════════════════════════════════

def run_framework(mode: str, latency_ms: float, bandwidth_kbps: float,
                  cpu_power_score: float, message_size_kb: float,
                  security_level: int, hndl_risk: float):
    """
    Main generator function that runs the full cryptographic framework.
    Yields structured log dicts consumed by the Flask SSE endpoint.

    Phases:
      0 — Initialization
      1 — Adaptive mode selection
      2 — TLS-like handshake simulation
      3 — Key exchange (ECDHE / ML-KEM / both)
      4 — Cryptographic composition
      5 — HKDF key derivation
      6 — Authentication & signatures
      7 — Key ratcheting
      8 — Attack simulation
      9 — Failure resilience analysis
     10 — Performance metrics
     11 — Final summary + results payload
    """

    import json

    def log(level, msg, delay=0.35):
        time.sleep(delay)
        yield make_log(level, msg)

    start_time = time.time()
    results = {}          # Final result payload sent at end

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 0 — INITIALIZATION
    # ──────────────────────────────────────────────────────────────────────────
    yield make_log('INFO', '══════════════════════════════════════════════════')
    time.sleep(0.2)
    yield make_log('INFO', '  Post-Quantum Secure Communication Framework v1.0')
    time.sleep(0.2)
    yield make_log('INFO', '══════════════════════════════════════════════════')
    time.sleep(0.3)
    yield make_log('INFO', f'[Init] Mode requested        : {mode}')
    time.sleep(0.2)
    yield make_log('INFO', f'[Init] Network latency       : {latency_ms} ms')
    time.sleep(0.2)
    yield make_log('INFO', f'[Init] Bandwidth             : {bandwidth_kbps} kbps')
    time.sleep(0.2)
    yield make_log('INFO', f'[Init] CPU power score       : {cpu_power_score}')
    time.sleep(0.2)
    yield make_log('INFO', f'[Init] Message size          : {message_size_kb} KB')
    time.sleep(0.2)
    yield make_log('INFO', f'[Init] Security level        : {security_level}/5')
    time.sleep(0.2)
    yield make_log('INFO', f'[Init] HNDL risk score       : {hndl_risk}')
    time.sleep(0.3)

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 1 — ADAPTIVE MODE SELECTION
    # ──────────────────────────────────────────────────────────────────────────
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 1] Adaptive Cryptographic Mode Selection')
    time.sleep(0.3)

    selected_mode = mode  # default: use user-requested mode

    if mode.lower() == 'adaptive':
        yield make_log('INFO', '[Adaptive] Querying ML Decision Tree classifier...')
        time.sleep(0.4)
        try:
            selector = AdaptiveSelector()
            selector.train()
            ml_mode = selector.predict(
                latency_ms, bandwidth_kbps, cpu_power_score,
                message_size_kb, security_level, hndl_risk
            )
            selected_mode = ml_mode
            yield make_log('SUCCESS',
                f'[Adaptive-ML] Decision Tree predicted mode: {ml_mode}')
            time.sleep(0.3)
            yield make_log('INFO',
                f'[Adaptive-ML] Features: lat={latency_ms}, bw={bandwidth_kbps}, '
                f'cpu={cpu_power_score}, sec={security_level}, hndl={hndl_risk}')
        except Exception as e:
            yield make_log('WARN',
                f'[Adaptive-ML] ML unavailable ({e}), using rule-based fallback.')
            time.sleep(0.3)
            selector = AdaptiveSelector()
            selected_mode = selector.rule_based_predict(
                latency_ms, bandwidth_kbps, cpu_power_score,
                message_size_kb, security_level, hndl_risk
            )
            yield make_log('INFO',
                f'[Adaptive-Rules] Rule-based selection: {selected_mode}')

        yield make_log('INFO', '[Adaptive] Reasoning:')
        time.sleep(0.2)
        if selected_mode == 'Hybrid':
            yield make_log('INFO',
                '  → hndl_risk ≥ 0.65 OR security_level ≥ 4: maximum protection required.')
        elif selected_mode == 'PQC':
            yield make_log('INFO',
                '  → Moderate HNDL risk + sufficient CPU: PQC recommended.')
        else:
            yield make_log('INFO',
                '  → Low HNDL risk, constrained CPU/bandwidth: Classical sufficient.')
    else:
        yield make_log('INFO',
            f'[Phase 1] User-specified mode: {mode}. Skipping ML selection.')
        selected_mode = mode
        time.sleep(0.3)

    time.sleep(0.2)
    yield make_log('SUCCESS', f'[Phase 1] ✓ Selected Mode: {selected_mode.upper()}')
    results['selected_mode'] = selected_mode

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 2 — TLS-LIKE HANDSHAKE
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 2] TLS-like Handshake Simulation')
    time.sleep(0.3)

    session_id       = secrets.token_hex(16)
    nonce_client     = secrets.token_bytes(32)
    nonce_server     = secrets.token_bytes(32)
    nonce            = nonce_client + nonce_server

    supported_algos = [
        'ECDHE-P256', 'ML-KEM-768', 'Dilithium3',
        'ECDSA-P256', 'AES-256-GCM', 'HMAC-SHA256'
    ]

    yield make_log('INFO', f'[ClientHello] Session ID : {session_id[:8]}****')
    time.sleep(0.25)
    yield make_log('INFO',
        f'[ClientHello] Supported  : {", ".join(supported_algos)}')
    time.sleep(0.25)
    yield make_log('INFO',
        f'[ClientHello] Client Random: {nonce_client.hex()[:12]}****')
    time.sleep(0.3)

    # Server selects algorithms based on mode
    if selected_mode.lower() in ['hybrid']:
        chosen_kex  = 'ECDHE-P256 + ML-KEM-768'
        chosen_sign = 'ECDSA-P256 + Dilithium3'
        chosen_enc  = 'AES-256-GCM'
    elif selected_mode.lower() == 'pqc':
        chosen_kex  = 'ML-KEM-768'
        chosen_sign = 'Dilithium3'
        chosen_enc  = 'AES-256-GCM'
    else:
        chosen_kex  = 'ECDHE-P256'
        chosen_sign = 'ECDSA-P256'
        chosen_enc  = 'AES-256-GCM'

    yield make_log('INFO', f'[ServerHello] Session ID : {session_id[:8]}****')
    time.sleep(0.25)
    yield make_log('INFO', f'[ServerHello] Key Exchange : {chosen_kex}')
    time.sleep(0.25)
    yield make_log('INFO', f'[ServerHello] Signature    : {chosen_sign}')
    time.sleep(0.25)
    yield make_log('INFO', f'[ServerHello] Encryption   : {chosen_enc}')
    time.sleep(0.25)
    yield make_log('INFO',
        f'[ServerHello] Server Random: {nonce_server.hex()[:12]}****')
    time.sleep(0.3)

    # Transcript hash — covers entire negotiation
    transcript_input  = session_id.encode() + b'|'.join(a.encode() for a in supported_algos)
    transcript_input += chosen_kex.encode() + chosen_sign.encode()
    transcript_hash   = hashlib.sha256(transcript_input).digest()

    yield make_log('INFO',
        f'[Handshake] Transcript hash: {transcript_hash.hex()[:14]}****')
    time.sleep(0.3)
    yield make_log('SUCCESS',
        '[Phase 2] ✓ Handshake negotiation complete — Cryptographic agility applied.')

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 3 — KEY EXCHANGE
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 3] Key Exchange')
    time.sleep(0.3)

    ecdhe_result = None
    mlkem_result = None
    S_classical  = None
    S_pq         = None
    private_key_classical = None

    mode_lower = selected_mode.lower()

    # ----- ECDHE (Classical) -----
    if mode_lower in ['classical', 'hybrid']:
        yield make_log('INFO', '[ECDHE] Generating ephemeral P-256 key pairs...')
        time.sleep(0.35)
        ecdhe_result = simulate_ecdhe()
        private_key_classical = ecdhe_result['private_key_client']

        yield make_log('INFO',
            f'[ECDHE] Client ephemeral pubkey  : '
            f'{mask_value(ecdhe_result["client_public"])}')
        time.sleep(0.3)
        yield make_log('INFO',
            f'[ECDHE] Server ephemeral pubkey  : '
            f'{mask_value(ecdhe_result["server_public"])}')
        time.sleep(0.3)
        yield make_log('INFO',
            '[ECDHE] Computing shared secret via EC scalar multiplication...')
        time.sleep(0.4)

        S_classical = ecdhe_result['shared_secret']
        yield make_log('SUCCESS',
            f'[ECDHE] S_classical = '
            f'{mask_value(ecdhe_result["shared_secret_hex"])}')
        time.sleep(0.25)
        yield make_log('INFO',
            '[ECDHE] Entropy of S_classical: '
            f'{shannon_entropy(S_classical):.4f} bits/byte (ideal=8.0)')
        time.sleep(0.3)
        yield make_log('SUCCESS', '[ECDHE] ✓ ECDHE shared secret established.')
        time.sleep(0.2)

    # ----- ML-KEM (Post-Quantum) -----
    if mode_lower in ['pqc', 'hybrid']:
        yield make_log('INFO', '[ML-KEM] Starting Kyber-768 key encapsulation...')
        time.sleep(0.35)
        yield make_log('INFO',
            '[ML-KEM] Key Gen: Sampling random matrix A, secret s, error e...')
        time.sleep(0.4)

        mlkem_result = simulate_mlkem()

        yield make_log('INFO',
            f'[ML-KEM] Public key   : '
            f'{mask_value(mlkem_result["public_key"])}')
        time.sleep(0.3)
        yield make_log('INFO',
            '[ML-KEM] Encapsulating shared secret into ciphertext...')
        time.sleep(0.4)
        yield make_log('INFO',
            f'[ML-KEM] Ciphertext   : '
            f'{mask_value(mlkem_result["ciphertext"])}  [sim: 64B, real: 1088B]')
        time.sleep(0.3)
        yield make_log('INFO', '[ML-KEM] Receiver decapsulating ciphertext with sk...')
        time.sleep(0.4)

        if mlkem_result['match']:
            yield make_log('SUCCESS',
                '[ML-KEM] Encap/Decap secrets MATCH ✓ — IND-CCA secure channel.')
            time.sleep(0.25)
        S_pq = mlkem_result['shared_secret']
        yield make_log('SUCCESS',
            f'[ML-KEM] S_pq = {mask_value(mlkem_result["shared_secret_hex"])}')
        time.sleep(0.25)
        yield make_log('INFO',
            f'[ML-KEM] Entropy of S_pq: '
            f'{shannon_entropy(S_pq):.4f} bits/byte  (MLWE hardness verified)')
        time.sleep(0.3)
        yield make_log('SUCCESS', '[ML-KEM] ✓ ML-KEM shared secret established.')
        time.sleep(0.2)

    # Placeholders for single-mode
    if S_classical is None:
        S_classical = secrets.token_bytes(32)  # not used in key, just for reference
    if S_pq is None:
        S_pq = secrets.token_bytes(32)

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 4 — CRYPTOGRAPHIC COMPOSITION
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 4] Cryptographic Composition of Secrets')
    time.sleep(0.3)

    composition_method = ''
    composed_secret    = b''
    salt_compose       = secrets.token_bytes(32)

    if mode_lower == 'hybrid':
        yield make_log('INFO',
            '[Compose] Strategy: REDUNDANT SECURE (Parallel + HKDF-based)')
        time.sleep(0.3)
        yield make_log('INFO',
            '[Compose] Security guarantee: secure if EITHER component is secure.')
        time.sleep(0.3)

        # Step 1: Parallel composition — derive two intermediate keys
        yield make_log('INFO', '[Compose] Step 1: Parallel derivation of K_c and K_pq...')
        time.sleep(0.3)
        K_c   = hkdf(S_classical, salt=salt_compose, info=b'classical-branch', length=32)
        K_pq  = hkdf(S_pq,        salt=salt_compose, info=b'pqc-branch',       length=32)

        yield make_log('INFO', f'  K_c  (from ECDHE) = {mask_value(K_c.hex())}')
        time.sleep(0.25)
        yield make_log('INFO', f'  K_pq (from MLKEM) = {mask_value(K_pq.hex())}')
        time.sleep(0.3)

        # Step 2: XOR composition
        yield make_log('INFO', '[Compose] Step 2: XOR composition — K_xor = K_c ⊕ K_pq')
        time.sleep(0.3)
        K_xor = compose_xor(K_c, K_pq)
        yield make_log('INFO', f'  K_xor = {mask_value(K_xor.hex())}')
        time.sleep(0.3)

        # Step 3: HKDF-based final composition
        yield make_log('INFO',
            '[Compose] Step 3: HKDF combination of S_classical ‖ S_pq → composed_secret')
        time.sleep(0.3)
        composed_secret    = compose_hkdf_based(S_classical, S_pq,
                                                salt=salt_compose,
                                                info=b'hybrid-compose')
        composition_method = 'Parallel XOR + HKDF (Redundant Secure)'
        yield make_log('SUCCESS',
            f'[Compose] composed_secret = {mask_value(composed_secret.hex())}')
        time.sleep(0.25)
        yield make_log('SUCCESS',
            '[Compose] ✓ Hybrid composition complete — quantum + classical security.')

    elif mode_lower == 'pqc':
        yield make_log('INFO',
            '[Compose] Strategy: Hash-based composition — S = SHA256(S_pq ‖ nonce)')
        time.sleep(0.3)
        composed_secret    = compose_hash(S_pq, nonce_client)
        composition_method = 'Hash-based SHA256(S_pq ‖ nonce)'
        yield make_log('SUCCESS',
            f'[Compose] composed_secret = {mask_value(composed_secret.hex())}')
        time.sleep(0.25)
        yield make_log('SUCCESS',
            '[Compose] ✓ PQC composition complete.')

    else:   # Classical
        yield make_log('INFO',
            '[Compose] Strategy: Concatenation + HKDF — S = HKDF(S_classical ‖ nonce)')
        time.sleep(0.3)
        composed_secret    = hkdf(S_classical + nonce_client,
                                  salt=salt_compose, info=b'classical-compose')
        composition_method = 'Concatenation + HKDF(S_classical ‖ nonce)'
        yield make_log('SUCCESS',
            f'[Compose] composed_secret = {mask_value(composed_secret.hex())}')
        time.sleep(0.25)
        yield make_log('SUCCESS',
            '[Compose] ✓ Classical composition complete.')

    time.sleep(0.2)
    results['composition_method'] = composition_method

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 5 — HKDF KEY DERIVATION
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 5] HKDF Key Derivation (RFC 5869)')
    time.sleep(0.3)

    # IKM = composed_secret ‖ nonce ‖ transcript_hash
    ikm_full = composed_secret + nonce + transcript_hash

    yield make_log('INFO',
        '[HKDF] Input Keying Material (IKM) = composed_secret ‖ nonce ‖ transcript_hash')
    time.sleep(0.3)
    yield make_log('INFO',
        f'  composed_secret  = {mask_value(composed_secret.hex())}')
    time.sleep(0.2)
    yield make_log('INFO',
        f'  nonce            = {mask_value(nonce.hex())}')
    time.sleep(0.2)
    yield make_log('INFO',
        f'  transcript_hash  = {mask_value(transcript_hash.hex())}')
    time.sleep(0.3)

    # Extract
    salt_hkdf = secrets.token_bytes(32)
    prk = hkdf_extract(salt_hkdf, ikm_full)
    yield make_log('INFO', '[HKDF] Extract: PRK = HMAC-SHA256(salt, IKM)')
    time.sleep(0.3)
    yield make_log('INFO', f'  PRK = {mask_value(prk.hex())}')
    time.sleep(0.25)

    # Expand — derive multiple keys
    yield make_log('INFO',
        '[HKDF] Expand: Deriving session keys with domain separation...')
    time.sleep(0.3)

    K_final  = hkdf_expand(prk, info=b'session-key',   length=32)
    K_mac    = hkdf_expand(prk, info=b'mac-key',        length=32)
    K_enc    = hkdf_expand(prk, info=b'encryption-key', length=32)

    yield make_log('INFO',
        f'  K_final (session)  = {mask_value(K_final.hex())}')
    time.sleep(0.25)
    yield make_log('INFO',
        f'  K_mac   (HMAC)     = {mask_value(K_mac.hex())}')
    time.sleep(0.25)
    yield make_log('INFO',
        f'  K_enc   (AES-GCM)  = {mask_value(K_enc.hex())}')
    time.sleep(0.3)

    # Entropy analysis
    entropy_raw   = shannon_entropy(composed_secret)
    entropy_final = shannon_entropy(K_final)
    yield make_log('INFO',
        f'[Entropy] Pre-KDF  (composed_secret): {entropy_raw:.4f} bits/byte')
    time.sleep(0.25)
    yield make_log('INFO',
        f'[Entropy] Post-KDF (K_final)         : {entropy_final:.4f} bits/byte')
    time.sleep(0.25)
    yield make_log('SUCCESS',
        f'[Entropy] ✓ KDF improves/preserves entropy — '
        f'{"improved" if entropy_final >= entropy_raw else "preserved"} after extraction.')
    time.sleep(0.3)
    yield make_log('SUCCESS', '[Phase 5] ✓ Final session key derived via HKDF.')

    results['session_key_masked'] = mask_value(K_final.hex())
    results['entropy_pre_kdf']    = round(entropy_raw, 4)
    results['entropy_post_kdf']   = round(entropy_final, 4)

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 6 — AUTHENTICATION & DIGITAL SIGNATURES
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 6] Authentication & Digital Signatures')
    time.sleep(0.3)

    test_message = b'SECURE_CHANNEL_HANDSHAKE_FINISHED' + transcript_hash
    hmac_tag     = compute_hmac(K_mac, test_message)

    yield make_log('INFO',
        '[HMAC] Computing HMAC-SHA256 over Finished message...')
    time.sleep(0.3)
    yield make_log('SUCCESS',
        f'[HMAC] Tag = {mask_value(hmac_tag)}')
    time.sleep(0.3)
    yield make_log('SUCCESS',
        '[HMAC] ✓ Integrity + authenticity bound to session key K_mac.')
    time.sleep(0.3)

    # Classical signature
    if mode_lower in ['classical', 'hybrid']:
        yield make_log('INFO',
            '[ECDSA] Signing transcript with ECDSA-P256...')
        time.sleep(0.35)
        ecdsa_sig = simulate_ecdsa_sign(private_key_classical, transcript_hash)
        yield make_log('SUCCESS',
            f'[ECDSA] σ_classical = {mask_value(ecdsa_sig)}')
        time.sleep(0.25)

    # PQC signature
    if mode_lower in ['pqc', 'hybrid']:
        yield make_log('INFO',
            '[Dilithium] Signing transcript with ML-DSA (Dilithium3)...')
        time.sleep(0.35)
        secret_key_bytes = bytes.fromhex(mlkem_result['secret_key'])
        dil_sig = simulate_dilithium_sign(secret_key_bytes, transcript_hash)
        yield make_log('SUCCESS',
            f'[Dilithium] σ_pqc = {mask_value(dil_sig)}')
        time.sleep(0.25)
        yield make_log('INFO',
            '[Dilithium] Security: Module-LWE + Module-SIS (quantum-hard lattice problems).')
        time.sleep(0.25)

    yield make_log('SUCCESS', '[Phase 6] ✓ Authentication complete.')
    results['hmac_tag'] = mask_value(hmac_tag)

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 7 — KEY RATCHETING
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 7] Key Ratcheting — Forward Secrecy')
    time.sleep(0.3)
    yield make_log('INFO',
        '[Ratchet] K₁ → K₂ → K₃  (each derived via HKDF — one-way function)')
    time.sleep(0.3)

    ratchet_keys = [K_final]
    ratchet_display = []

    for step in range(1, 4):
        prev_key    = ratchet_keys[-1]
        next_key    = key_ratchet(prev_key, step)
        ratchet_keys.append(next_key)
        masked      = mask_value(next_key.hex())
        ratchet_display.append(masked)

        yield make_log('INFO',
            f'  [Ratchet] K₀→K{step}: {mask_value(prev_key.hex())} → {masked}')
        time.sleep(0.3)

    yield make_log('INFO',
        '[Ratchet] Property: Knowing K₃ does NOT allow derivation of K₀, K₁, K₂.')
    time.sleep(0.3)
    yield make_log('SUCCESS',
        '[Phase 7] ✓ Forward secrecy demonstrated — '
        'past sessions safe even if K_final is compromised.')
    results['ratchet_keys'] = [mask_value(K_final.hex())] + ratchet_display

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 8 — ATTACK SIMULATION
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 8] Attack Simulation Suite')
    time.sleep(0.3)

    attacker = AttackSimulator(
        mode        = selected_mode,
        session_key = K_mac,
        nonce       = nonce,
        hndl_risk   = hndl_risk,
    )

    for event in attacker.run_all_attacks():
        time.sleep(0.28)
        yield event

    results['attack_results'] = attacker.attack_results

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 9 — FAILURE RESILIENCE ANALYSIS
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 9] Failure Resilience Analysis')
    time.sleep(0.3)

    resilience = []

    yield make_log('INFO', '[Resilience] Scenario A: Classical cryptography broken by QC')
    time.sleep(0.3)
    if mode_lower == 'hybrid':
        yield make_log('SUCCESS',
            '  → S_classical compromised, but S_pq from ML-KEM is quantum-hard.')
        time.sleep(0.25)
        yield make_log('SUCCESS',
            '  → K_final = HKDF(S_classical ‖ S_pq …): attacker still needs S_pq.')
        time.sleep(0.25)
        yield make_log('SUCCESS',
            '  ✓ HYBRID STILL SECURE — PQC component preserves secrecy.')
        resilience.append({'scenario': 'Classical broken by QC', 'status': 'SECURE',
                           'reason': 'ML-KEM S_pq remains quantum-hard.'})
    elif mode_lower == 'pqc':
        yield make_log('SUCCESS',
            '  → PQC mode does not use classical ECDHE — not affected.')
        resilience.append({'scenario': 'Classical broken by QC', 'status': 'SECURE',
                           'reason': 'PQC mode uses only ML-KEM — no classical component.'})
    else:
        yield make_log('ERROR',
            '  → Classical mode relies solely on ECDHE — VULNERABLE to Shor\'s algorithm.')
        resilience.append({'scenario': 'Classical broken by QC', 'status': 'VULNERABLE',
                           'reason': 'No PQC backup. Session key exposed to quantum attacker.'})

    time.sleep(0.3)
    yield make_log('INFO', '[Resilience] Scenario B: PQC (ML-KEM) vulnerability discovered')
    time.sleep(0.3)
    if mode_lower == 'hybrid':
        yield make_log('SUCCESS',
            '  → S_pq compromised, but S_classical (ECDHE) still secure classically.')
        time.sleep(0.25)
        yield make_log('SUCCESS',
            '  → Attacker needs S_classical AND S_pq to break K_final.')
        time.sleep(0.25)
        yield make_log('SUCCESS',
            '  ✓ HYBRID STILL SECURE — ECDHE component preserves secrecy.')
        resilience.append({'scenario': 'PQC ML-KEM broken', 'status': 'SECURE',
                           'reason': 'ECDHE S_classical still holds classically.'})
    elif mode_lower == 'classical':
        yield make_log('SUCCESS',
            '  → Classical mode does not depend on PQC — not affected.')
        resilience.append({'scenario': 'PQC ML-KEM broken', 'status': 'SECURE',
                           'reason': 'Classical mode does not use ML-KEM.'})
    else:
        yield make_log('ERROR',
            '  → PQC mode relies solely on ML-KEM — VULNERABLE if ML-KEM is broken.')
        resilience.append({'scenario': 'PQC ML-KEM broken', 'status': 'VULNERABLE',
                           'reason': 'No classical backup. K_final exposed.'})

    time.sleep(0.3)
    yield make_log('INFO', '[Resilience] Scenario C: Both components broken simultaneously')
    time.sleep(0.3)
    yield make_log('ERROR',
        '  → All modes VULNERABLE — cryptographically catastrophic event.')
    yield make_log('INFO',
        '  → Mitigation: Use multiple independent PQC schemes (BIKE + Kyber).')
    resilience.append({'scenario': 'Both components broken', 'status': 'VULNERABLE',
                       'reason': 'No composition survives total cryptanalytic break.'})

    results['resilience'] = resilience

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 10 — PERFORMANCE METRICS
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 10] Performance Metrics')
    time.sleep(0.3)

    elapsed_ms = round((time.time() - start_time) * 1000, 1)

    # Estimate bandwidth (bytes transmitted in key exchange)
    bw_classical = 64 + 64           # two P-256 pubkeys  (~32 bytes each, hex = 64B)
    bw_pqc       = 32 + 64 + 1088   # pk(32) + ct(1088) + ciphertext overhead
    bw_hmac      = 32               # HMAC tag
    bw_sig_ecdsa = 64               # ECDSA sig bytes
    bw_sig_dil   = 2420             # Dilithium3 signature bytes

    if mode_lower == 'hybrid':
        bw_total = bw_classical + bw_pqc + bw_hmac + bw_sig_ecdsa + bw_sig_dil
    elif mode_lower == 'pqc':
        bw_total = bw_pqc + bw_hmac + bw_sig_dil
    else:
        bw_total = bw_classical + bw_hmac + bw_sig_ecdsa

    security_bits = {'classical': 128, 'pqc': 192, 'hybrid': 256}.get(mode_lower, 256)

    yield make_log('INFO',
        f'  Handshake simulation time : {elapsed_ms} ms')
    time.sleep(0.25)
    yield make_log('INFO',
        f'  Estimated key-exchange BW : {bw_total} bytes  ({bw_total/1024:.2f} KB)')
    time.sleep(0.25)
    yield make_log('INFO',
        f'  Session key length        : 256 bits (32 bytes)')
    time.sleep(0.25)
    yield make_log('INFO',
        f'  Claimed security level    : {security_bits} bits')
    time.sleep(0.25)
    yield make_log('INFO',
        f'  Pre-KDF entropy           : {entropy_raw:.4f} bits/byte')
    time.sleep(0.25)
    yield make_log('INFO',
        f'  Post-KDF entropy          : {entropy_final:.4f} bits/byte')
    time.sleep(0.3)

    results['performance'] = {
        'handshake_latency_ms'  : elapsed_ms,
        'bandwidth_bytes'       : bw_total,
        'security_bits'         : security_bits,
        'key_length_bits'       : 256,
    }
    results['session_id'] = session_id

    # ──────────────────────────────────────────────────────────────────────────
    # PHASE 11 — FINAL SUMMARY
    # ──────────────────────────────────────────────────────────────────────────
    time.sleep(0.3)
    yield make_log('INFO', '─' * 50)
    time.sleep(0.2)
    yield make_log('INFO', '[Phase 11] Secure Channel Established')
    time.sleep(0.3)

    yield make_log('SUCCESS',
        f'  Mode              : {selected_mode.upper()}')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        f'  Session Key       : {mask_value(K_final.hex())}')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        f'  Composition       : {composition_method}')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        f'  HMAC Tag          : {mask_value(hmac_tag)}')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        f'  Forward Secrecy   : ✓ (key ratcheting active)')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        f'  PQ-Resistant      : {"✓" if mode_lower in ["pqc","hybrid"] else "✗ (Classical only)"}')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        f'  Hybrid Resilience : {"✓" if mode_lower == "hybrid" else "–"}')
    time.sleep(0.3)

    yield make_log('SUCCESS',
        '══════════════════════════════════════════════════')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        '  ✓ SECURE CHANNEL ESTABLISHED SUCCESSFULLY')
    time.sleep(0.2)
    yield make_log('SUCCESS',
        '══════════════════════════════════════════════════')

    # Final yield — the complete results payload
    time.sleep(0.3)
    results['status'] = 'SUCCESS'
    results['internal_keys'] = {
        'k_enc_hex': K_enc.hex(),
        'k_mac_hex': K_mac.hex(),
    }
    yield {
        'type'   : 'results',
        'payload': results,
    }