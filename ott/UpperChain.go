package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrNoKey   = errors.New("hmac key not found")
	ErrBadSig  = errors.New("invalid signature")
	ErrTsOrder = errors.New("timestamp not increasing")
)

func hmacHex(secret, data string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// CP 앵커 검증 및 저장
func verifyAndStoreAnchor(cpID, lowerRoot, ts, sig string) error {
	secret, ok := getHMACKey(cpID)
	if !ok {
		return ErrNoKey
	}
	want := hmacHex(secret, lowerRoot+"|"+ts)
	if want != sig {
		return ErrBadSig
	}
	// 단조 증가(ts)
	if prev, ok := getAnchor(cpID); ok {
		oldT, err1 := time.Parse(time.RFC3339, prev.Timestamp)
		newT, err2 := time.Parse(time.RFC3339, ts)
		if err1 == nil && err2 == nil && !newT.After(oldT) {
			return ErrTsOrder
		}
	}
	return setAnchor(AnchorState{CPID: cpID, LowerRoot: lowerRoot, Timestamp: ts, Signature: sig})
}
