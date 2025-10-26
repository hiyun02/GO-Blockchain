package main

import (
	"math"
	"strings"
)

// 난이도 설정 (앞자리가 몇 개의 0으로 시작해야 하는지)
var difficulty = 4

// 블록의 Nonce 값을 바꿔가며 해시가 난이도 조건을 만족할 때까지 반복
func proofOfWork(block UpperBlock) (string, int) {
	nonce := 0
	var hash string
	target := strings.Repeat("0", difficulty) // 예: "0000"

	for {
		block.Nonce = nonce
		hash = computeHash(block)

		// 해시가 난이도 조건을 만족하면 성공
		if strings.HasPrefix(hash, target) {
			return hash, nonce
		}

		nonce++
		if nonce == math.MaxInt32 {
			nonce = 0 // Overflow 방지
		}
	}
}

// validatePoW : 블록이 PoW 조건을 만족하는지 검증
func validatePoW(block Block) bool {
	target := strings.Repeat("0", difficulty)
	hash := calculateHash(block)
	return strings.HasPrefix(hash, target)
}
