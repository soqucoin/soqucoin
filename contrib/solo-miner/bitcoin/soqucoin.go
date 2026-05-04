package bitcoin

import (
        "strings"
)

// Soqucoin - Scrypt PoW chain with Dilithium signatures
type Soqucoin struct{}

func (Soqucoin) ChainName() string {
        return "soqucoin"
}

func (Soqucoin) CoinbaseDigest(coinbase string) (string, error) {
        return DoubleSha256(coinbase)
}

func (Soqucoin) HeaderDigest(header string) (string, error) {
        return ScryptDigest(header)
}

func (Soqucoin) ShareMultiplier() float64 {
        return 65536
}

func (Soqucoin) ValidMainnetAddress(address string) bool {
        // Soqucoin mainnet Dilithium addresses start with 'sq1' (bech32m)
        // Soqucoin stagenet Dilithium addresses use 'ssq1' prefix
        if strings.HasPrefix(address, "ssq1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(address, "sq1") && len(address) >= 42 {
                return true
        }
        // Also accept uppercase (ASICs sometimes uppercase addresses)
        upper := strings.ToUpper(address)
        if strings.HasPrefix(upper, "SSQ1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(upper, "SQ1") && len(address) >= 42 {
                return true
        }
        // Legacy mainnet addresses start with S (for transition period)
        if strings.HasPrefix(address, "S") && len(address) >= 34 && len(address) <= 36 {
                return true
        }
        return false
}

func (Soqucoin) ValidTestnetAddress(address string) bool {
        // Soqucoin testnet Dilithium addresses also use 'sq1' prefix (like mainnet)
        // The bech32m HRP is 'sq' for both networks in current implementation
        // Soqucoin stagenet Dilithium addresses use 'ssq1' prefix
        if strings.HasPrefix(address, "ssq1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(address, "sq1") && len(address) >= 42 {
                return true
        }
        // Also accept uppercase (ASICs sometimes uppercase addresses)
        upper := strings.ToUpper(address)
        if strings.HasPrefix(upper, "SSQ1") && len(address) >= 42 {
                return true
        }
        if strings.HasPrefix(upper, "SQ1") && len(address) >= 42 {
                return true
        }
        // Legacy testnet addresses start with n or 2 (for transition period)
        if (strings.HasPrefix(address, "n") || strings.HasPrefix(address, "2")) && len(address) >= 34 && len(address) <= 36 {
                return true
        }
        return false
}

func (Soqucoin) MinimumConfirmations() uint {
        // FINDING-10 FIX: Match actual coinbase maturity of 100 confirmations.
        // Was incorrectly set to 10, risking reward distribution for orphaned blocks.
        return uint(100)
}
