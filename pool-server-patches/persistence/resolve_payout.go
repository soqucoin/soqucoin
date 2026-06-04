package persistence

import "fmt"

// ResolvePayoutAddress looks up a payout wallet address for a given miner name and chain.
// The miner_name is what the miner connects with via stratum (e.g., "Blaap", "foundation").
// Returns the is_payout=true address for the given chain, or falls back to the only address
// for that chain if exactly one exists.
func (r AuthRepository) ResolvePayoutAddress(minerName, chain string) (string, error) {
	// 1. Find the user by miner_name (case-insensitive)
	var userID int64
	err := r.db.QueryRow(
		`SELECT id FROM users WHERE LOWER(miner_name) = LOWER($1)`, minerName,
	).Scan(&userID)
	if err != nil {
		// Fallback: try matching by username (case-insensitive)
		err = r.db.QueryRow(
			`SELECT id FROM users WHERE LOWER(username) = LOWER($1)`, minerName,
		).Scan(&userID)
		if err != nil {
			return "", err
		}
	}

	// 2. Look for is_payout=true address for this chain
	var address string
	err = r.db.QueryRow(
		`SELECT address FROM user_addresses
		 WHERE user_id = $1 AND chain = $2 AND is_payout = true
		 LIMIT 1`, userID, chain,
	).Scan(&address)
	if err == nil {
		return address, nil
	}

	// 3. Fallback: if exactly one address for this chain, use it
	var count int
	r.db.QueryRow(
		`SELECT count(*) FROM user_addresses WHERE user_id = $1 AND chain = $2`,
		userID, chain,
	).Scan(&count)
	if count == 1 {
		err = r.db.QueryRow(
			`SELECT address FROM user_addresses WHERE user_id = $1 AND chain = $2`,
			userID, chain,
		).Scan(&address)
		if err == nil {
			return address, nil
		}
	}

	return "", fmt.Errorf("no payout address for user %q on chain %s (has %d addresses, none marked is_payout)", minerName, chain, count)
}
