// soq-solo-miner — Soqucoin Solo Mining Stratum Proxy
//
// Connects to your local soqucoind node via RPC and exposes a stratum
// port for your miners. All block rewards go directly to YOUR address.
//
// Usage:
//   soq-solo-miner [config.json]
//
// Quick start:
//   1. Start soqucoind with RPC enabled
//   2. Create config.json (see example below)
//   3. Run: soq-solo-miner config.json
//   4. Point your miners to stratum+tcp://localhost:3333
//
// Example config.json:
//   {
//     "pool_name": "SoloMiner",
//     "port": "3333",
//     "max_connections": 100,
//     "connection_timeout": "120s",
//     "pool_difficulty": 10000,
//     "block_signature": "SoloMiner",
//     "merged_blockchain_order": ["soqucoin"],
//     "blockchains": {
//       "soqucoin": [{
//         "name": "local",
//         "rpc_url": "http://127.0.0.1:28332",
//         "rpc_username": "soqucoin",
//         "rpc_password": "YOUR_RPC_PASSWORD",
//         "block_notify_url": "tcp://127.0.0.1:28334",
//         "timeout": "30s",
//         "reward_to": "YOUR_SOQUCOIN_ADDRESS"
//       }]
//     },
//     "share_flush_interval": "30s",
//     "hashrate_window": "10m",
//     "pool_stats_interval": "5m",
//     "app_stats_interval": "5m"
//   }

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"designs.capital/dogepool/config"
	"designs.capital/dogepool/persistence"
	"designs.capital/dogepool/pool"
	"designs.capital/dogepool/rpc"
)

const version = "1.0.0"

func main() {
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║     Soqucoin Solo Miner v" + version + "           ║")
	fmt.Println("║     Stratum Proxy for Solo Mining        ║")
	fmt.Println("║     https://soqu.org                     ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Println()

	configFileName := parseCommandLineOptions()
	if configFileName == "" {
		configFileName = "config.json"
	}

	if _, err := os.Stat(configFileName); os.IsNotExist(err) {
		log.Fatalf("Config file not found: %s\nRun 'soq-solo-miner --help' for usage.", configFileName)
	}

	configuration := config.LoadConfig(configFileName)

	// Solo miner uses file-based logging, no PostgreSQL
	err := persistence.MakePersister(configuration)
	if err != nil {
		log.Fatal(err)
	}

	rpcManagers := makeRPCManagers(configuration)

	log.Printf("Reward address: %s", getRewardAddress(configuration))
	log.Printf("RPC endpoint: %s", getRPCEndpoint(configuration))

	poolServer := pool.NewServer(configuration, rpcManagers)
	go poolServer.Start()
	log.Println("⛏️  Stratum server listening on port " + configuration.Port)
	log.Println("Point your miners to: stratum+tcp://localhost:" + configuration.Port)
	log.Println()
	log.Println("Waiting for miners to connect...")

	// Periodic stats
	go printStats(configuration)

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("\nShutting down solo miner...")
}

func parseCommandLineOptions() string {
	help := flag.Bool("help", false, "Show usage information")
	ver := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *help {
		fmt.Println("Usage: soq-solo-miner [OPTIONS] [config.json]")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  --help       Show this help message")
		fmt.Println("  --version    Show version")
		fmt.Println()
		fmt.Println("The config.json file must specify your soqucoind RPC connection")
		fmt.Println("and your reward address. See the README for a complete example.")
		os.Exit(0)
	}

	if *ver {
		fmt.Println("soq-solo-miner v" + version)
		os.Exit(0)
	}

	return flag.Arg(0)
}

func getRewardAddress(cfg *config.Config) string {
	primary := cfg.GetPrimary()
	nodes := cfg.BlockchainNodes[primary]
	if len(nodes) > 0 {
		return nodes[0].RewardTo
	}
	return "(not configured)"
}

func getRPCEndpoint(cfg *config.Config) string {
	primary := cfg.GetPrimary()
	nodes := cfg.BlockchainNodes[primary]
	if len(nodes) > 0 {
		return nodes[0].RPC_URL
	}
	return "(not configured)"
}

func printStats(configuration *config.Config) {
	interval := 5 * time.Minute
	if configuration.AppStatsInterval != "" {
		if d, err := time.ParseDuration(configuration.AppStatsInterval); err == nil {
			interval = d
		}
	}
	for {
		time.Sleep(interval)
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		log.Printf("Stats: goroutines=%d mem=%dMB",
			runtime.NumGoroutine(), memStats.Sys/1024/1024)
	}
}

func makeRPCManagers(configuration *config.Config) map[string]*rpc.Manager {
	managers := make(map[string]*rpc.Manager)
	for _, chain := range configuration.BlockChainOrder {
		nodeConfigs := configuration.BlockchainNodes[chain]
		rpcConfig := make([]rpc.Config, len(nodeConfigs))
		for i, nodeConfig := range nodeConfigs {
			rpcConfig[i] = rpc.Config{
				Name:     nodeConfig.Name,
				URL:      nodeConfig.RPC_URL,
				Username: nodeConfig.RPC_Username,
				Password: nodeConfig.RPC_Password,
				Timeout:  nodeConfig.Timeout,
			}
		}
		manager := rpc.MakeRPCManager(chain, rpcConfig, "1h")
		managers[chain] = &manager
	}
	return managers
}
