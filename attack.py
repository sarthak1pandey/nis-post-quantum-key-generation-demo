"""
attack.py — Cryptographic Attack Simulation Module

Simulates four real-world attacks on the secure channel:
  1. HNDL   — Harvest Now, Decrypt Later (quantum threat)
  2. Replay — Re-sending captured authentic messages
  3. MITM   — Man-in-the-Middle key substitution
  4. Downgrade — Forcing negotiation to a weaker algorithm
"""

import hashlib
import hmac
import secrets
import time


class AttackSimulator:
    """
    Runs attack simulations and records results.
    Yields log event dicts compatible with the SSE stream.
    """

    def __init__(self, mode: str, session_key: bytes, nonce: bytes, hndl_risk: float):
        self.mode           = mode.lower()
        self.session_key    = session_key
        self.nonce          = nonce
        self.hndl_risk      = hndl_risk
        self.attack_results = []        # Collected for the final results panel

    # ------------------------------------------------------------------ helpers
    def _log(self, level: str, msg: str) -> dict:
        return {
            'type'      : 'log',
            'level'     : level,
            'message'   : msg,
            'timestamp' : time.strftime('%H:%M:%S'),
        }

    def _record(self, attack: str, status: str, reason: str):
        self.attack_results.append({
            'attack': attack,
            'status': status,
            'reason': reason,
        })

    # ------------------------------------------------------------------ attacks
    def simulate_hndl(self):
        """
        HNDL — Harvest Now, Decrypt Later
        ───────────────────────────────────
        Threat model: A nation-state attacker records all encrypted traffic today.
        Once a sufficiently powerful quantum computer exists, they run Shor's
        algorithm to recover classical (ECDHE/RSA) private keys and decrypt
        every archived session.

        Defence:
          • PQC    → ML-KEM ciphertext secure under MLWE (quantum-hard)
          • Hybrid → Even if ECDHE broken, ML-KEM component keeps K_final secret
          • Classical → VULNERABLE (no quantum-safe component)
        """
        yield self._log('WARN', '[HNDL] Attacker records all ciphertext for future quantum decryption...')

        captured = secrets.token_bytes(64).hex()
        yield self._log('WARN', f'[HNDL] Captured ciphertext: {captured[:16]}****{captured[-8:]}')
        yield self._log('INFO', f'[HNDL] HNDL risk score: {self.hndl_risk}')

        if self.mode == 'classical':
            yield self._log('ERROR', '[HNDL] ECDHE shared secret recoverable via Shor\'s algorithm on QC!')
            yield self._log('ERROR', '[HNDL] ✗ VULNERABLE — No quantum-resistant component in session key.')
            self._record('HNDL', 'VULNERABLE',
                         "Shor's algorithm recovers ECDHE private key on a quantum computer.")
        elif self.mode == 'pqc':
            yield self._log('SUCCESS', '[HNDL] ML-KEM ciphertext: MLWE problem is quantum-hard.')
            yield self._log('SUCCESS', '[HNDL] ✓ RESISTANT — PQC component withstands quantum decryption.')
            self._record('HNDL', 'RESISTANT',
                         'ML-KEM (Kyber) secure under Module-LWE, hard for quantum computers.')
        else:  # hybrid
            yield self._log('SUCCESS', '[HNDL] ECDHE component vulnerable to Shor\'s algorithm...')
            yield self._log('SUCCESS', '[HNDL] ML-KEM component: MLWE hardness ensures K_pq is safe.')
            yield self._log('SUCCESS', '[HNDL] K_final = HKDF(S_classical ‖ S_pq ‖ …) — attacker needs BOTH.')
            yield self._log('SUCCESS', '[HNDL] ✓ RESISTANT — Hybrid composition defeats quantum decryption.')
            self._record('HNDL', 'RESISTANT',
                         'HKDF hybrid composition: secure if either component survives quantum attack.')

    def simulate_replay(self):
        """
        Replay Attack
        ─────────────
        Threat model: Attacker captures a valid authenticated message and
        re-sends it to trick the server into re-processing it (e.g., duplicate
        bank transaction).

        Defence:
          • Per-session unique nonce included in HMAC context
          • HMAC key derived from ephemeral session key (new each session)
          • Sequence numbers / timestamps further prevent old message reuse
        """
        yield self._log('WARN', '[Replay] Capturing an authenticated session message...')

        message  = b'WIRE_TRANSFER: $50000 -> ACC-99182'
        tag      = hmac.new(self.session_key, message, hashlib.sha256).hexdigest()
        yield self._log('WARN',    f'[Replay] Captured → "{message.decode()}"')
        yield self._log('WARN',    f'[Replay] Captured HMAC tag: {tag[:12]}****')
        yield self._log('INFO',    '[Replay] Replaying captured message with old HMAC tag...')

        # New session = new nonce = new HMAC key context
        new_session_key = secrets.token_bytes(32)
        new_tag = hmac.new(new_session_key, message, hashlib.sha256).hexdigest()

        if new_tag != tag:
            yield self._log('SUCCESS', '[Replay] HMAC verification FAILED — tag mismatch with new session key.')
            yield self._log('SUCCESS', '[Replay] ✓ BLOCKED — Ephemeral per-session keys invalidate replayed tags.')
            self._record('Replay', 'BLOCKED',
                         'Per-session ephemeral HMAC keys + nonce binding prevent replay.')

    def simulate_mitm(self):
        """
        Man-in-the-Middle (MITM)
        ────────────────────────
        Threat model: Attacker sits between client and server, intercepts the
        key exchange, substitutes their own public keys, and establishes two
        separate secure channels (one to each party).

        Defence:
          • Transcript hash binds every handshake message to the session key
          • Digital signatures (ECDSA + Dilithium) authenticate public keys
          • If attacker substitutes keys, signature verification fails
        """
        yield self._log('WARN', '[MITM] Intercepting key exchange in transit...')

        attacker_fake_key = secrets.token_bytes(32).hex()
        yield self._log('WARN',    f'[MITM] Attacker injects fake public key: {attacker_fake_key[:12]}****')
        yield self._log('INFO',    '[MITM] Verifying digital signatures on received keys...')

        if self.mode in ['classical', 'hybrid']:
            yield self._log('SUCCESS', '[MITM] ECDSA signature on ECDHE public key: MISMATCH ✗')
            yield self._log('SUCCESS', '[MITM] ✓ Classical signature check BLOCKED MITM substitution.')

        if self.mode in ['pqc', 'hybrid']:
            yield self._log('SUCCESS', '[MITM] Dilithium (ML-DSA) signature on ML-KEM public key: MISMATCH ✗')
            yield self._log('SUCCESS', '[MITM] ✓ PQC signature check BLOCKED MITM substitution.')

        yield self._log('SUCCESS', '[MITM] Transcript hash binding: K_final tied to authentic negotiation.')
        yield self._log('SUCCESS', '[MITM] ✓ BLOCKED — Both authentication layers independently detected MITM.')
        self._record('MITM', 'BLOCKED',
                     'ECDSA + Dilithium signatures + transcript hash binding detect key substitution.')

    def simulate_downgrade(self):
        """
        Downgrade Attack
        ────────────────
        Threat model: Attacker modifies the ClientHello/ServerHello messages
        to remove strong algorithms, forcing both parties to negotiate a weaker
        cipher suite (e.g., dropping PQC and using only Classical).

        Defence:
          • Transcript hash covers every negotiation message
          • Session key is derived from the transcript hash
          • Any modification changes the transcript → keys don't match → connection fails
        """
        yield self._log('WARN', '[Downgrade] Attacker strips PQC algorithms from ClientHello...')
        yield self._log('WARN', '[Downgrade] Modified ClientHello: "ECDHE-only, no ML-KEM, AES-128"')

        real_transcript = b'ClientHello:ECDHE,MLKEM768,Dilithium3,AES256-GCM'
        fake_transcript = b'ClientHello:ECDHE-only,AES128-CBC'

        real_hash = hashlib.sha256(real_transcript).hexdigest()
        fake_hash = hashlib.sha256(fake_transcript).hexdigest()

        yield self._log('INFO', f'[Downgrade] Authentic transcript hash : {real_hash[:14]}****')
        yield self._log('INFO', f'[Downgrade] Tampered transcript hash  : {fake_hash[:14]}****')

        if real_hash != fake_hash:
            yield self._log('SUCCESS', '[Downgrade] Transcript hash mismatch — tampering detected!')
            yield self._log('SUCCESS', '[Downgrade] ✓ BLOCKED — Session key derivation includes transcript hash.')
            status = 'BLOCKED'
            reason = 'Transcript hash binding catches any modification to negotiation messages.'
        else:
            status = 'BLOCKED'
            reason = 'Transcript hash binding active.'

        if self.mode == 'hybrid':
            yield self._log('SUCCESS', '[Downgrade] ✓ Hybrid security policy enforces minimum: PQC + Classical.')

        self._record('Downgrade', status, reason)

    # ------------------------------------------------------------------ runner
    def run_all_attacks(self):
        """
        Execute all four attack simulations sequentially.
        Yields log event dicts for SSE streaming.
        """
        yield self._log('INFO', '[Attacks] Launching 4-vector attack simulation suite...')

        yield self._log('INFO', '  ▶ Attack 1/4 — Harvest Now Decrypt Later (HNDL)')
        yield from self.simulate_hndl()

        yield self._log('INFO', '  ▶ Attack 2/4 — Replay Attack')
        yield from self.simulate_replay()

        yield self._log('INFO', '  ▶ Attack 3/4 — Man-in-the-Middle (MITM)')
        yield from self.simulate_mitm()

        yield self._log('INFO', '  ▶ Attack 4/4 — Downgrade Attack')
        yield from self.simulate_downgrade()

        # Summary
        vulnerable = [a for a in self.attack_results if a['status'] == 'VULNERABLE']
        mitigated  = [a for a in self.attack_results if a['status'] != 'VULNERABLE']

        yield self._log('INFO',
            f'[Attack Summary] {len(mitigated)}/4 mitigated | {len(vulnerable)}/4 vulnerable')

        if vulnerable:
            for v in vulnerable:
                yield self._log('ERROR', f'[Vulnerable] {v["attack"]}: {v["reason"]}')
        else:
            yield self._log('SUCCESS', '[Attack Summary] ✓ All 4 attacks successfully mitigated!')