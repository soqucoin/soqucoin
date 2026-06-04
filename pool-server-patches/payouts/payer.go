package payouts

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"designs.capital/dogepool/config"
	"designs.capital/dogepool/persistence"
	"designs.capital/dogepool/rpc"
	"designs.capital/dogepool/soqsigner"
)

// soqSignerClient is initialized once at startup and shared across payout cycles.
var soqSignerClient *soqsigner.Client

// InitSoqSigner creates the soq-signer client from config.
// Called once at startup from manager.go.
func InitSoqSigner(cfg *soqsigner.Config) {
	if cfg == nil || cfg.URL == "" {
		log.Println("[payouts] ⚠️  soq-signer not configured — SOQ payouts will use RPC sendmany (will fail if disablewallet=1)")
		return
	}
	soqSignerClient = soqsigner.NewClient(*cfg)
	log.Printf("[payouts] ✅ soq-signer client initialized: %s", cfg.URL)

	if err := soqSignerClient.HealthCheck(); err != nil {
		log.Printf("[payouts] ⚠️  soq-signer health check failed at startup: %v", err)
		log.Println("[payouts] SOQ payouts will be retried next interval if soq-signer recovers")
	} else {
		log.Println("[payouts] ✅ soq-signer health check passed")
	}
}

// payoutBalances groups balances by chain and dispatches payments.
// SOQ payments go through soq-signer; all other chains use RPC sendmany.
func payoutBalances(config *config.Config, rpcManagers map[string]*rpc.Manager) error {
	var balances []persistence.Balance
	for _, chain := range config.BlockChainOrder {
		payoutConfig, exists := config.Payouts.Chains[chain]
		if !exists {
			return errors.New("payouts.payoutBalances() - failed to find chain payout config: " + chain)
		}
		b, err := persistence.Balances.GetPoolBalancesOverThreshold(config.PoolName, chain, payoutConfig.MinerMinimumPayment)
		if err != nil {
			return err
		}
		balances = append(balances, b...)
	}

	if len(balances) == 0 {
		return nil
	}

	// Group balances by chain and resolve addresses
	type resolvedBalance struct {
		balance persistence.Balance
		address string
	}
	chainBalances := make(map[string][]resolvedBalance)

	for _, balance := range balances {
		address, err := findBalanceAddress(balance, config)
		if err != nil {
			log.Printf("[payouts] ⚠️  Failed to resolve address for %s on %s: %v", balance.Address, balance.Chain, err)
			continue
		}
		chainBalances[balance.Chain] = append(chainBalances[balance.Chain], resolvedBalance{balance, address})
	}

	// Process each chain independently
	for chain, resolved := range chainBalances {
		if len(resolved) == 0 {
			continue
		}

		transactions := make(map[string]float64)
		for _, r := range resolved {
			transactions[r.address] = r.balance.Amount
		}

		var txid string
		var err error

		if chain == "soqucoin" {
			txid, err = sendSOQPayments(transactions)
		} else {
			txid, err = sendRPCPayments(chain, transactions, rpcManagers)
		}

		if err != nil {
			log.Printf("[payouts] ❌ %s payout failed: %v", chain, err)
			continue
		}

		// Record payments and reset balances
		for _, r := range resolved {
			err = persistence.Payments.Insert(persistence.Payment{
				PoolID:                      r.balance.PoolID,
				Chain:                       r.balance.Chain,
				Address:                     r.address,
				Amount:                      r.balance.Amount,
				Created:                     time.Now(),
				TransactionConfirmationData: txid,
			})
			if err != nil {
				log.Printf("[payouts] ❌ Failed to record payment for %s: %v", r.address, err)
				continue
			}

			usage := "Paid balance to miner"
			err = persistence.Balances.AddAmount(config.PoolName, r.balance.Chain, r.balance.Address, usage, r.balance.Amount*-1)
			if err != nil {
				log.Printf("[payouts] ❌ Failed to reset balance for %s: %v", r.balance.Address, err)
			}
		}

		log.Printf("[payouts] ✅ %s: %d payments processed, txid: %s", chain, len(resolved), txid)
	}

	return nil
}

// sendSOQPayments dispatches SOQ payments through soq-signer.
func sendSOQPayments(transactions map[string]float64) (string, error) {
	if soqSignerClient == nil {
		return "", errors.New("soq-signer not configured — cannot send SOQ payments")
	}
	log.Printf("[payouts] 📤 Sending %d SOQ payments via soq-signer", len(transactions))
	return soqSignerClient.SendMany(transactions)
}

// sendRPCPayments dispatches payments through the chain RPC (sendmany).
func sendRPCPayments(chain string, transactions map[string]float64, rpcManagers map[string]*rpc.Manager) (string, error) {
	client, exists := rpcManagers[chain]
	if !exists {
		return "", fmt.Errorf("no RPC manager for chain: %s", chain)
	}
	node := client.GetActiveClient()
	log.Printf("[payouts] 📤 Sending %d %s payments via RPC sendmany", len(transactions), chain)
	txid, err := node.SendMany(transactions)
	if err != nil {
		return "", fmt.Errorf("sendmany %s: %w", chain, err)
	}
	log.Printf("[payouts] ✅ %s sendmany txid: %s", chain, txid)
	return txid, nil
}

// findBalanceAddress resolves the payout address for a specific chain.
//
// Resolution order:
// 1. If the balance address contains dashes (composite address like "LTC-SOQ-DOGE-BEL"),
//    split and use the positional index for the chain.
// 2. If the balance address is a plain string (miner_name like "Blaap" or "foundation"),
//    look up the user's registered payout address via the account system.
// 3. If no account match, check if it already looks like a wallet address and use it directly.
func findBalanceAddress(balance persistence.Balance, config *config.Config) (string, error) {
	address := balance.Address

	// Case 1: Composite dash-separated address (e.g., "LTC_ADDR-SOQ_ADDR-DOGE_ADDR-BEL_ADDR")
	if strings.Contains(address, "-") {
		addresses := strings.Split(address, "-")
		i := 0
		for _, chain := range config.BlockChainOrder {
			if chain == balance.Chain {
				if i >= len(addresses) {
					return "", fmt.Errorf("miner %s has %d addresses but chain %s is at index %d",
						address, len(addresses), balance.Chain, i)
				}
				return addresses[i], nil
			}
			i++
		}
		return "", errors.New("chain address not found in composite: " + balance.Chain)
	}

	// Case 2: Plain miner name — resolve through account system
	resolved, err := persistence.Auth.ResolvePayoutAddress(address, balance.Chain)
	if err == nil && resolved != "" {
		return resolved, nil
	}

	// Case 3: If it already looks like a wallet address (starts with known prefixes), use directly
	lowerAddr := strings.ToLower(address)
	if strings.HasPrefix(lowerAddr, "ssq1") || strings.HasPrefix(lowerAddr, "sq1") ||
		strings.HasPrefix(lowerAddr, "ltc1") || strings.HasPrefix(lowerAddr, "L") || strings.HasPrefix(lowerAddr, "M") ||
		strings.HasPrefix(lowerAddr, "D") || strings.HasPrefix(lowerAddr, "bel1") || strings.HasPrefix(lowerAddr, "B") {
		return address, nil
	}

	return "", fmt.Errorf("cannot resolve payout address for miner %q on chain %s: %v", address, balance.Chain, err)
}
