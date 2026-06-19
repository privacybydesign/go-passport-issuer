# Passport Issuer — Verification Flow Contracts

> Active/Passive authentication → face verification → gated credential issuance.
> A backwards-compatibility-first proposal.

This document specifies the exact wire contracts for the end-to-end issuance flow
across the three components:

- the wallet (`vcmrtd`),
- the issuer (`go-passport-issuer`),
- the external [`face-verification-service`](https://github.com/privacybydesign/face-verification-service).

**Design goal:** passive + active authentication run **before** the face session,
and a credential is only issued once **both** authentication and face verification
have succeeded — while keeping every wallet-facing request/response schema unchanged.

---

## 1 · End-to-end sequence

```mermaid
sequenceDiagram
    autonumber
    participant W as Wallet (vcmrtd)
    participant I as Issuer (go-passport-issuer)
    participant F as face-verification-service

    W->>I: POST /api/start-validation
    I->>I: store session{nonce}
    I-->>W: { session_id, nonce }

    Note over W: NFC tap (once)<br/>read DGs, sign AA over nonce

    W->>I: POST /api/verify-passport<br/>{session_id, nonce, data_groups, ef_sod, aa_signature}
    I->>I: PASSIVE auth ✓
    I->>I: ACTIVE auth ✓
    I->>F: POST /api/face/session<br/>{verifier_id, callback_url, portrait_image = raw DG2 b64}
    F-->>I: {face_session_id, binding_secret, websocket_url, ...}
    I->>I: store face{binding_secret, dg2_sha256, status: pending}<br/>session KEPT (not deleted)
    I-->>W: {authentic_content, authentic_chip, is_expired, face_session}

    Note over W,F: binding_key = HKDF(face_session_id, salt = SHA256(DG2))
    W->>F: WebSocket handshake + stream JPEG frames
    F-->>W: frame_result… / verification_complete{result: success}
    F->>I: POST {callback_url}<br/>X-Face-Signature: HMAC(binding_secret)<br/>{face_session_id, result, ...}
    I->>I: store face.status = success

    W->>I: POST /api/issue-passport<br/>{session_id, nonce, data_groups, ef_sod, aa_signature, face_session_id?}
    I->>I: PASSIVE ✓  ACTIVE ✓
    I->>I: GATE: face.status == success<br/>AND SHA256(DG2) == face.dg2_sha256
    I->>I: create IRMA JWT, delete session
    I-->>W: { jwt, irma_server_url }

    W->>W: POST {irma_server_url}/session → start IRMA issuance
```

Step 4 (verify) is now _optional but recommended_: the face session is created there.
The same single NFC tap (step 2) supplies the AA signature reused by both verify and
issue, so the session must survive from start through issue.

---

## 2 · Design principles

- **No wallet-facing schema breaks.** `start-validation`, `verify-passport` and
  `issue-passport` keep their existing request/response shapes. The only additive
  field is an _optional_ `face_session_id` on issuance requests.
- **Issuer is authoritative.** The face result is never taken from the wallet's
  word. The issuer learns the verdict only from the face service via a
  `binding_secret`-authenticated callback (the secret the README already reserves
  "to authenticate result callbacks").
- **Off-by-default stays byte-for-byte.** When `face_verification.url` is empty,
  issuance is ungated and the whole flow behaves exactly as today.
- **Cryptographic binding to the document.** A face verdict is only honored for
  issuance if its reference photo hash equals `SHA256(DG2)` of the passport being
  issued — a stolen `face_session_id` from another document cannot unlock issuance.
- **One breaking change, scoped & safe:** the session is no longer destroyed by
  `verify-passport`; it lives until `issue-*` consumes it (or its TTL expires).
  No current client depends on verify being terminal.

---

## 3 · Endpoint contracts

### `POST /api/start-validation` — UNCHANGED

| Direction | Body |
|-----------|------|
| Request | _empty_ |
| Response 200 | `{ "session_id": "<32 hex>", "nonce": "<16 hex>" }` |

Creates the session record and the AA nonce. **Behavioral note:** the stored value
gains internal fields (see §4) but the response is identical.

---

### `POST /api/verify-passport` — BEHAVIOR CHANGE (schema unchanged)

Also applies to `/api/verify-driving-licence`, which starts a face session bound to the
eDL's **DG6** portrait (passports/ID cards use **DG2**).

```jsonc
// Request — models.ValidationRequest (unchanged)
{
  "session_id": "a1b2…",
  "nonce": "1234567890abcdef",
  "data_groups": { "DG1": "…hex…", "DG2": "…hex…" },
  "ef_sod": "778201ab…",
  "aa_signature": "304502…"   // optional
}
```

```jsonc
// Response 200 — VerificationResponse (unchanged; face_session already present)
{
  "authentic_content": true,         // passive auth (signature) ok
  "authentic_chip": true,            // active auth (chip challenge) ok
  "is_expired": false,
  "face_session": {                  // omitted when face disabled / no DG2
    "face_session_id": "fs_abc123",
    "face_session_token": "<base64url>",
    "websocket_url": "wss://face.example/stream/fs_abc123",
    "binding_key_ready": true
  }
}
```

**What changes:**

- On success with face enabled + DG2 present, the issuer creates the face session
  and **persists a face record** keyed by `face_session_id` holding
  `{ binding_secret, dg2_sha256, status:"pending", session_id }`.
  `binding_secret` is never returned.
- **The session token is no longer deleted here.** It is consumed by the subsequent
  `issue-*` call (or expires via TTL).
- Face-service failure remains **non-fatal**: verification still returns 200 with no
  `face_session` (unchanged).

---

### `POST {face_verification.callback_url}` — NEW ENDPOINT

Server-to-server: the face service calls this when a session reaches a terminal
verdict. The issuer registers it at `POST /api/face/callback`; point
`face_verification.callback_url` at that path.

The signature is carried **in the body** as a `signature` field — a hex-encoded
`HMAC-SHA256(binding_secret, canonical_json)` where `canonical_json` is the body
**without** the `signature` field, serialized with sorted keys and compact
separators (Python `json.dumps(payload, sort_keys=True, separators=(",", ":"))`).

```http
POST /api/face/callback
Content-Type: application/json
```

```jsonc
// Request body
{
  "face_session_id": "fs_abc123",
  "result": "success",                 // "success" | "failed" | "error"
  "timestamp": "2026-06-19T12:00:00+00:00",
  "details": {
    "match_confidence": 0.97,
    "liveness_passed": true,
    "liveness_score": 0.9,
    "frames_processed": 42,
    "verification_duration_ms": 1234
  },
  "signature": "<hex HMAC-SHA256 over canonical JSON, keyed by binding_secret>"
}
```

```jsonc
// Response 200
{ "ok": true }
```

| Status | When |
|--------|------|
| `200` | signature valid & record updated |
| `400` | malformed body / missing `face_session_id` |
| `401` | `signature` missing or HMAC mismatch against the stored `binding_secret` |
| `404` | unknown `face_session_id` |

> **Verified against the service.** This matches
> [`privacybydesign/face-verification-service`](https://github.com/privacybydesign/face-verification-service)
> (`backend/services/callback_service.py`): the verdict nests under `details`, the
> `signature` is hex over canonical sorted/compact JSON of the unsigned body, and
> delivery is a background webhook with retries when `callback_url` was supplied at
> session creation. The Go receiver reproduces the canonical form via `json.Number`
> (preserving integral floats like `1.0`) with HTML-escaping disabled.

---

### `POST /api/issue-passport` — GATED + 1 OPTIONAL FIELD

Identical contract for `/api/issue-id-card`, `/api/issue-driving-licence`, and the
legacy `/api/verify-and-issue` alias. All document types are gated when face
verification is required: passports/ID cards bind on **DG2**, driving licences on **DG6**.

```jsonc
// Request — ValidationRequest + ONE optional additive field
{
  "session_id": "a1b2…",
  "nonce": "1234567890abcdef",
  "data_groups": { … },
  "ef_sod": "…",
  "aa_signature": "…",
  "face_session_id": "fs_abc123"   // NEW, optional; required only when face enabled
}
```

```jsonc
// Response 200 — IssuanceResponse (unchanged)
{ "jwt": "eyJhbGc…", "irma_server_url": "https://irma.example.com" }
```

**Gate (only when `face_verification.url` is configured):** after passive + active
auth succeed, the issuer additionally requires all of:

1. `face_session_id` present in the request (or resolvable from the session record — see §4 alt).
2. a face record exists for it with `status == "success"`.
3. `SHA256(request.data_groups["DG2"]) == face_record.dg2_sha256` — binds the verdict
   to _this_ document.

| Status | Body | When |
|--------|------|------|
| `200` | `{ jwt, irma_server_url }` | auth ok + (face disabled OR face gate passed) |
| `400` | `invalid request` | bad body / session / nonce / passive / active auth fail (as today) |
| `428` | `face:pending` | face enabled, record exists, callback not yet received → client may retry |
| `403` | `face:required` / `face:failed` / `face:mismatch` | no face_session_id, verdict failed, or DG2 hash mismatch |

On `200` the session token is removed (as today). On the gate failures the session is
left intact so the wallet can retry after the verdict lands.

---

## 4 · Internal session & face state

The validation-session value is **unchanged** (a bare nonce). The face record is a
new, separate keyspace. Both go through the existing
`StoreToken/RetrieveToken/RemoveToken` — no interface change.

```jsonc
// key: <ns>:token:<session_id>   (UNCHANGED — still a bare nonce string)
"1234567890abcdef"
```

```jsonc
// key: <ns>:token:facerec:<face_session_id>   (NEW)
{ "face_session_id": "fs_abc123",
  "session_id": "a1b2…",
  "binding_secret": "<opaque, never returned>",
  "dg2_sha256": "<hex>",
  "status": "pending",           // pending → success | failed | error
  "match_confidence": null,
  "liveness_passed": null }
```

> **Correlation: option B (implemented).** The wallet passes `face_session_id` on the
> issue request; the issuer looks up the `facerec:` record and enforces the
> `SHA256(DG2)` binding. The nonce-keyed session value is untouched, so `validateSession`
> and the storage backends are unchanged. (Option A — embedding `face_session_id` in
> the session record for zero wire change — remains a valid alternative, but B keeps
> the security-critical check, the DG2 hash, explicit and avoids migrating the stored
> nonce format.)

> **No storage migration.** Because option B keeps the nonce value bare, there is no
> change to existing session records and nothing to migrate across a deploy.

---

## 5 · Cryptography & binding (already implemented client-side)

| Value | Definition | Who |
|-------|------------|-----|
| reference photo | the **raw DG2 bytes** read from the chip, base64-encoded as `portrait_image` | issuer → face svc |
| `binding_key` | `HKDF-SHA256(ikm=face_session_id, salt=SHA256(reference_photo), info="yivi_face_binding_v1")` | wallet ↔ face svc |
| WS handshake | `HMAC-SHA256(binding_key, face_session_id)` | wallet → face svc |
| frame MAC | `HMAC-SHA256(binding_key, frame_bytes ‖ seq_be64)` | wallet → face svc |
| `binding_secret` | issuer↔face shared secret; authenticates the **callback** (distinct from binding_key) | issuer ↔ face svc |
| issuance binding | `SHA256(DG2)` must match on both the face session (created in verify) and the issue request | issuer-internal |

Because the binding key is salted with `SHA256(raw DG2)`, only the wallet that
physically read the chip can stream against the session — and only that same chip's
portrait can later satisfy the issuance gate.

```mermaid
flowchart LR
    DG2["raw DG2 bytes"] -->|SHA256| SALT["salt"]
    FSID["face_session_id"] -->|ikm| HKDF
    SALT -->|salt| HKDF["HKDF-SHA256<br/>info: yivi_face_binding_v1"]
    HKDF --> BK["binding_key (32B)"]
    BK -->|"HMAC(face_session_id)"| HS["WS handshake"]
    BK -->|"HMAC(frame ‖ seq)"| FM["frame MAC"]
    DG2 -->|SHA256| H1["dg2_sha256 @ verify"]
    DG2B["DG2 @ issue"] -->|SHA256| H2["dg2_sha256 @ issue"]
    H1 -.must equal.-> H2
```

---

## 6 · Config additions

```jsonc
{
  "face_verification": {
    "url": "https://face.example.com",        // empty ⇒ disabled, flow unchanged
    "verifier_id": "passport-issuer",
    "callback_url": "https://issuer.example.com/api/face/callback",
    "timeout_seconds": 10,
    "require_face_for_issuance": true    // NEW, default true when url set; false ⇒ face advisory only
  }
}
```

`require_face_for_issuance:false` lets an operator run face verification as
informational (start the session, surface the result) without hard-gating issuance —
useful for staged rollout.

---

## 7 · Backwards-compatibility matrix

| Surface | Face disabled (default) | Face enabled |
|---------|-------------------------|--------------|
| `start-validation` req/resp | identical | identical |
| `verify-passport` req/resp | identical | identical (+ face_session, already shipped) |
| session lifecycle | not deleted at verify | not deleted at verify |
| `issue-*` request | identical | + optional `face_session_id` |
| `issue-*` behavior | ungated — as today | gated on face verdict |
| `/api/face/callback` | n/a | new server-to-server route |
| token storage value (nonce) | unchanged (bare nonce) | unchanged (bare nonce) |
| token storage (new keyspace) | n/a | `facerec:<id>` JSON record |

---

## 8 · Resolved decisions (as implemented)

1. **Callback schema & signature** — ✅ confirmed against
   `face-verification-service`: in-body hex `signature` over canonical sorted/compact
   JSON, verdict under `details` (see §3). The Go receiver reproduces the canonical
   form with `json.Number` + HTML-escaping disabled.
2. **Pending-verdict UX** — implemented as **both**: `428 face:pending` is returned
   only when the verdict is genuinely not yet known *and* no status poll is wired.
   When `faceStatusGetter` is configured the issuer first pulls
   `GET /api/face/session/{id}/status` as a synchronous fallback, so the wallet
   normally needs no retry.
3. **Correlation option** — implemented **option B**: the wallet passes
   `face_session_id` on the issue request; the nonce-keyed session value is left
   unchanged. The face record (binding_secret, `dg2_sha256`, status) lives in a
   separate `facerec:<id>` keyspace. The `SHA256(DG2)` binding is the security check.
4. **ID card & driving licence** — gated identically to passport. ID cards bind on
   DG2 (same eMRTD path as passports); driving licences bind on DG6. The face
   service extracts the embedded JPEG/JPEG2000 from either container, so the
   binding stays over the raw data-group bytes on both sides.
