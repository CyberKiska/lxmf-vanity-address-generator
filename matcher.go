package main

import (
	"encoding/hex"
	"fmt"
)

type addressMatcher struct {
	prefixBytes   [addressByteLength]byte
	prefixLen     int
	prefixOdd     byte
	hasPrefixOdd  bool
	postfixBytes  [addressByteLength]byte
	postfixLen    int
	postfixOdd    byte
	hasPostfixOdd bool
}

func newAddressMatcher(prefix, postfix string) (addressMatcher, error) {
	var m addressMatcher
	if err := validatePatterns(prefix, postfix); err != nil {
		return m, err
	}

	prefixEvenChars := len(prefix) &^ 1
	if prefixEvenChars > 0 {
		n, err := hex.Decode(m.prefixBytes[:], []byte(prefix[:prefixEvenChars]))
		if err != nil {
			return m, fmt.Errorf("invalid prefix: %w", err)
		}
		m.prefixLen = n
	}
	if len(prefix)%2 == 1 {
		nibble, ok := hexNibble(prefix[prefixEvenChars])
		if !ok {
			return m, fmt.Errorf("invalid prefix")
		}
		m.prefixOdd = nibble
		m.hasPrefixOdd = true
	}

	postfixStart := 0
	if len(postfix)%2 == 1 {
		nibble, ok := hexNibble(postfix[0])
		if !ok {
			return m, fmt.Errorf("invalid postfix")
		}
		m.postfixOdd = nibble
		m.hasPostfixOdd = true
		postfixStart = 1
	}
	if postfixStart < len(postfix) {
		n, err := hex.Decode(m.postfixBytes[:], []byte(postfix[postfixStart:]))
		if err != nil {
			return m, fmt.Errorf("invalid postfix: %w", err)
		}
		m.postfixLen = n
	}

	return m, nil
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func (m addressMatcher) matches(addr []byte) bool {
	if len(addr) != addressByteLength {
		return false
	}

	for i := 0; i < m.prefixLen; i++ {
		if addr[i] != m.prefixBytes[i] {
			return false
		}
	}
	if m.hasPrefixOdd && addr[m.prefixLen]>>4 != m.prefixOdd {
		return false
	}

	if m.postfixLen > 0 {
		start := addressByteLength - m.postfixLen
		for i := 0; i < m.postfixLen; i++ {
			if addr[start+i] != m.postfixBytes[i] {
				return false
			}
		}
	}
	if m.hasPostfixOdd {
		idx := addressByteLength - m.postfixLen - 1
		if addr[idx]&0x0F != m.postfixOdd {
			return false
		}
	}

	return true
}
