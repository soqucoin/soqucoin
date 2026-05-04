package pool

import (
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"designs.capital/dogepool/bitcoin"
	"designs.capital/dogepool/config"
	"designs.capital/dogepool/persistence"
	"designs.capital/dogepool/rpc"
)

type PoolServer struct {
	sync.RWMutex
	config            *config.Config
	activeNodes       BlockChainNodesMap
	rpcManagers       map[string]*rpc.Manager
	connectionTimeout time.Duration
	templates         Pair
	workCache         bitcoin.Work
	shareBuffer       []persistence.Share
}

func NewServer(cfg *config.Config, rpcManagers map[string]*rpc.Manager) *PoolServer {
	if len(cfg.PoolName) < 1 {
		log.Println("Pool must have a name")
	}
	if len(cfg.BlockchainNodes) < 1 {
		log.Println("Pool must have at least 1 blockchain node to work from")
	}
	if len(cfg.BlockChainOrder) < 1 {
		log.Println("Pool must have a blockchain order to tell primary vs aux")
	}

	pool := &PoolServer{
		config:      cfg,
		rpcManagers: rpcManagers,
	}

	return pool
}

func (pool *PoolServer) Start() {
	initiateSessions()
	pool.loadBlockchainNodes()
	pool.startBufferManager()

	amountOfChains := len(pool.config.BlockChainOrder) - 1
	pool.templates.AuxBlocks = make([]bitcoin.AuxBlock, amountOfChains)

	// FINDING-01 FIX: Retry initial work fetch with exponential backoff
	// instead of panic. The node may be slow to start (Dilithium signing).
	var err error
	maxRetries := 30
	for attempt := 1; attempt <= maxRetries; attempt++ {
		err = pool.fetchRpcBlockTemplatesAndCacheWork()
		if err == nil {
			break
		}
		backoff := time.Duration(attempt) * 2 * time.Second
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
		log.Printf("RPC work fetch failed (attempt %d/%d): %v — retrying in %v", attempt, maxRetries, err, backoff)
		time.Sleep(backoff)
	}
	if err != nil {
		log.Fatalf("FATAL: Failed to fetch initial work after %d attempts: %v", maxRetries, err)
	}

	work, err := pool.generateWorkFromCache(false)
	if err != nil {
		log.Fatalf("FATAL: Failed to generate initial work: %v", err)
	}

	go pool.listenForConnections()
	pool.broadcastWork(work)

	// There after..
	panicOnError(pool.listenForBlockNotifications())
}

func (pool *PoolServer) broadcastWork(work bitcoin.Work) {
	request := miningNotify(work)
	err := notifyAllSessions(request)
	logOnError(err)
}

func (p *PoolServer) fetchAllBlockTemplatesFromRPC() (bitcoin.Template, *bitcoin.AuxBlock, error) {
	var template bitcoin.Template
	var err error
	response, err := p.GetPrimaryNode().RPC.GetBlockTemplate()
	if err != nil {
		return template, nil, errors.New("RPC error: " + err.Error())
	}

	err = json.Unmarshal(response, &template)
	if err != nil {
		return template, nil, err
	}

	var auxBlock bitcoin.AuxBlock

	if p.config.GetAux1() != "" {
		response, err = p.GetAux1Node().RPC.CreateAuxBlock(p.GetAux1Node().RewardTo)
		if err != nil {
			log.Println("No aux block found: " + err.Error())
			return template, nil, nil
		}

		err = json.Unmarshal(response, &auxBlock)
		if err != nil {
			return template, nil, err
		}
	}

	return template, &auxBlock, nil
}

func notifyAllSessions(request stratumRequest) error {
	sessionsMux.RLock()
	clients := make([]*stratumClient, 0, len(sessions))
	for _, client := range sessions {
		clients = append(clients, client)
	}
	sessionsMux.RUnlock()

	for _, client := range clients {
		err := sendPacket(request, client)
		logOnError(err)
	}
	log.Printf("Sent work to %v client(s)", len(clients))
	return nil
}

func panicOnError(e error) {
	if e != nil {
		panic(e)
	}
}

func logOnError(e error) {
	if e != nil {
		log.Println(e)
	}
}

func logFatalOnError(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
