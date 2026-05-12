package document

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"log/slog"
	"math/big"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/cryptoutils"
)

// LogAATryAlternateHashes is a forensic-only helper used after gmrtd's
// ValidateActiveAuthSignature has rejected an ECDSA signature. It does NOT
// change the authentication result — it only tries every reasonable
// (hash, signature-encoding) combination against the provided public key
// and logs which combination, if any, verifies.
//
// This is the decisive diagnostic for two failure classes:
//   - chip uses a non-heuristic hash (e.g. SHA-256 over a P-384 key on
//     Portuguese cards that ship without a DG14 ActiveAuthenticationInfo)
//   - the signature was tampered with / DG15 mismatch (no combination works)
//
// Inputs are session-scoped and not durable PII; the public key, nonce and
// signature only identify this one challenge-response exchange. The
// per-combination attempts log at DEBUG; a positive match logs at INFO
// because it is actionable.
func LogAATryAlternateHashes(sessionId string, subjectPublicKeyInfoBytes, sig, nonce []byte) {
	if len(subjectPublicKeyInfoBytes) == 0 || len(sig) == 0 || len(nonce) == 0 {
		return
	}

	spki, err := cms.Asn1decodeSubjectPublicKeyInfo(subjectPublicKeyInfoBytes)
	if err != nil {
		slog.Debug("AA diagnostic: SPKI decode failed", "session_id", sessionId, "error", err)
		return
	}
	if !spki.IsEC() {
		// RSA AA takes a completely different verification path; not in scope here.
		return
	}

	curve, ecPoint, err := spki.EcCurveAndPubKey(true)
	if err != nil {
		slog.Debug("AA diagnostic: EC pubkey decode failed", "session_id", sessionId, "error", err)
		return
	}
	pub := &ecdsa.PublicKey{Curve: *curve, X: ecPoint.X, Y: ecPoint.Y}

	type parsedSig struct {
		format string
		r, s   *big.Int
	}
	var sigs []parsedSig
	if r, s, ok := parsePlainEcdsaSig(sig); ok {
		sigs = append(sigs, parsedSig{"plain", r, s})
	}
	if r, s, ok := parseDEREcdsaSig(sig); ok {
		sigs = append(sigs, parsedSig{"DER", r, s})
	}
	if len(sigs) == 0 {
		slog.Info("AA diagnostic: no parseable signature encoding",
			"session_id", sessionId,
			"sig_len", len(sig),
			"curve", pub.Params().Name,
		)
		return
	}

	candidates := []struct {
		name string
		alg  crypto.Hash
	}{
		{"SHA-224", crypto.SHA224},
		{"SHA-256", crypto.SHA256},
		{"SHA-384", crypto.SHA384},
		{"SHA-512", crypto.SHA512},
	}

	matched := false
	for _, p := range sigs {
		for _, c := range candidates {
			hash := cryptoutils.CryptoHash(c.alg, nonce)
			if ecdsa.Verify(pub, hash, p.r, p.s) {
				slog.Info("AA diagnostic: alternate hash/encoding verified",
					"session_id", sessionId,
					"hash", c.name,
					"sig_format", p.format,
					"curve", pub.Params().Name,
				)
				matched = true
			} else {
				slog.Debug("AA diagnostic: combination did not verify",
					"session_id", sessionId,
					"hash", c.name,
					"sig_format", p.format,
				)
			}
		}
	}
	if !matched {
		slog.Info("AA diagnostic: no hash/encoding combination verified",
			"session_id", sessionId,
			"curve", pub.Params().Name,
			"sig_len", len(sig),
			"nonce_len", len(nonce),
		)
	}
}

// parsePlainEcdsaSig parses a fixed-length r||s ECDSA signature.
func parsePlainEcdsaSig(b []byte) (r, s *big.Int, ok bool) {
	if len(b) < 2 || len(b)%2 != 0 {
		return nil, nil, false
	}
	half := len(b) / 2
	r = new(big.Int).SetBytes(b[:half])
	s = new(big.Int).SetBytes(b[half:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, nil, false
	}
	return r, s, true
}

// parseDEREcdsaSig parses an ASN.1/DER SEQUENCE { r INTEGER, s INTEGER }.
// Trailing bytes are tolerated; gmrtd's own parser is similarly lenient.
func parseDEREcdsaSig(b []byte) (r, s *big.Int, ok bool) {
	if len(b) == 0 || b[0] != 0x30 {
		return nil, nil, false
	}
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(b, &sig); err != nil {
		return nil, nil, false
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, nil, false
	}
	return sig.R, sig.S, true
}
