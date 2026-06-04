package pool

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"

	"designs.capital/dogepool/bitcoin"
	"designs.capital/dogepool/rpc"
	"github.com/go-zeromq/zmq4"
)

type BlockChainNodesMap map[string]blockChainNode // "blockChainName" => activeNode

type blockChainNode struct {
	NotifyURL          string
	RPC                *rpc.RPCClient
	ChainName          string
	Network            string
	RewardPubScriptKey string // TODO - this is very bitcoin specific.  Abstract to interface.
	RewardTo           string
	NetworkDifficulty  float64
}

func (p *PoolServer) GetPrimaryNode() blockChainNode {
	return p.activeNodes[p.config.GetPrimary()]
}

func (p *PoolServer) GetAux1Node() blockChainNode {
	return p.activeNodes[p.config.GetAux1()]
}

type hashblockCounterMap map[string]uint32 // "blockChainName" => hashblock msg counter

func (pool *PoolServer) loadBlockchainNodes() {
	pool.activeNodes = make(BlockChainNodesMap)
	for _, blockChainName := range pool.config.BlockChainOrder {
		rpcManager, exists := pool.rpcManagers[blockChainName]
		if !exists {
			panic("Blockchain not found for: " + blockChainName)
		}
		rpcClient := rpcManager.GetActiveClient()
		nodeConfig := pool.config.BlockchainNodes[blockChainName][rpcManager.GetIndex()]

		chainInfo, err := rpcClient.GetBlockChainInfo()
		logFatalOnError(err)

		address, err := rpcClient.ValidateAddress(nodeConfig.RewardTo)
		logFatalOnError(err)

		// TODO this is wayy to bitcoin specific.  Move this to the coin package.
		rewardPubScriptKey := address.ScriptPubKey

		newNode := blockChainNode{
			NotifyURL:          nodeConfig.NotifyURL,
			RPC:                rpcClient,
			Network:            chainInfo.Chain,
			RewardPubScriptKey: rewardPubScriptKey,
			RewardTo:           nodeConfig.RewardTo,
			NetworkDifficulty:  chainInfo.NetworkDifficulty,
			ChainName:          blockChainName,
		}
		pool.activeNodes[blockChainName] = newNode
	}
}

func (pool *PoolServer) listenForBlockNotifications() error {
	notifyChannel := make(chan hashBlockResponse)
	hashblockCounterMap := make(hashblockCounterMap)

	for blockChainName := range pool.activeNodes {
		subscription, err := pool.createZMQSubscriptionToHashBlock(blockChainName, notifyChannel)
		if err != nil {
			return err
		}
		defer subscription.Close()
	}

	for {
		msg := <-notifyChannel
		chainName := msg.blockChainName
		prevCount := hashblockCounterMap[chainName]
		newCount := msg.blockHashCounter
		prevBlockHash := msg.previousBlockHash

		m := "**New %v block: %v - %v**"
		log.Printf(m, chainName, newCount, prevBlockHash)

		if prevCount != 0 && (prevCount+1) != newCount {
			m = "We missed a %v block notification, previous count: %v current count: %v"
			log.Printf(m, chainName, prevCount, newCount)
		}

		hashblockCounterMap[chainName] = newCount

		err := pool.fetchRpcBlockTemplatesAndCacheWork()
		logOnError(err)
		work, err := pool.generateWorkFromCache(true)
		logOnError(err)
		pool.broadcastWork(work)
	}
}

// Ultimate program OUTPUT
func (p *PoolServer) submitBlockToChain(block bitcoin.BitcoinBlock) error {
	submission, err := block.Submit()
	if err != nil {
		return err
	}

	submit := []any{
		any(submission),
	}
	success, err := p.GetPrimaryNode().RPC.SubmitBlock(submit)

	if !success || err != nil {
		nodeName := p.GetPrimaryNode().ChainName
		m := "⚠️  %v primary node rejection: %v"
		m = fmt.Sprintf(m, nodeName, err.Error())
		return errors.New(m)
	}

	return nil
}

// submitAuxBlock submits an AuxPoW proof for a single-aux setup (legacy).
func (p *PoolServer) submitAuxBlock(primaryBlock bitcoin.BitcoinBlock, aux1Block bitcoin.AuxBlock) error {
	auxpow := bitcoin.MakeAuxPow(primaryBlock)
	serialized := auxpow.Serialize()
	os.WriteFile("/tmp/last_auxpow_hex.txt", []byte(serialized), 0644)
	os.WriteFile("/tmp/last_auxpow_hash.txt", []byte(aux1Block.Hash), 0644)
	log.Printf("AuxPoW saved — hash: %v, len: %v", aux1Block.Hash, len(serialized))
	success, err := p.GetAux1Node().RPC.SubmitAuxBlock(aux1Block.Hash, serialized)
	if !success {
		nodeName := p.GetAux1Node().ChainName
		m := "⚠️  %v node failed to submit aux block: %v"
		m = fmt.Sprintf(m, nodeName, err.Error())
		return errors.New(m)
	}
	return err
}

// submitAuxBlockMulti submits an AuxPoW proof for one chain in a multi-aux Merkle tree.
// auxIndex is the index into p.templates.AuxBlocks (0-based).
func (p *PoolServer) submitAuxBlockMulti(primaryBlock bitcoin.BitcoinBlock, auxBlock bitcoin.AuxBlock, auxIndex int) error {
	merkle := p.templates.AuxMerkle
	if merkle == nil {
		return errors.New("no aux Merkle tree available — cannot submit multi-aux proof")
	}

	branch, exists := merkle.Branches[auxIndex]
	if !exists {
		return fmt.Errorf("no Merkle branch for aux index %d", auxIndex)
	}

	auxpow := bitcoin.MakeAuxPowForChain(primaryBlock, branch)
	serialized := auxpow.Serialize()

	chainName := p.config.BlockChainOrder[auxIndex+1] // +1 because [0] is primary
	node, nodeExists := p.activeNodes[chainName]
	if !nodeExists {
		return fmt.Errorf("no active node for chain: %s", chainName)
	}

	// Debug: save the proof for diagnostics
	os.WriteFile(fmt.Sprintf("/tmp/last_auxpow_%s_hex.txt", chainName), []byte(serialized), 0644)
	os.WriteFile(fmt.Sprintf("/tmp/last_auxpow_%s_hash.txt", chainName), []byte(auxBlock.Hash), 0644)
	log.Printf("[multi-aux] Submitting %s AuxPoW — hash: %s, slot: %d, branch_len: %d",
		chainName, auxBlock.Hash, merkle.Slots[auxIndex], len(branch.Hashes))

	success, err := node.RPC.SubmitAuxBlock(auxBlock.Hash, serialized)
	if !success {
		m := fmt.Sprintf("⚠️  %s node rejected aux block: %v", chainName, err)
		return errors.New(m)
	}

	log.Printf("[multi-aux] 🎉 %s BLOCK ACCEPTED at height %d!", chainName, auxBlock.Height)
	return err
}

type hashBlockResponse struct {
	blockChainName    string
	previousBlockHash string
	blockHashCounter  uint32
}

func (p *PoolServer) createZMQSubscriptionToHashBlock(blockChainName string, hashBlockChannel chan hashBlockResponse) (zmq4.Socket, error) {
	sub := zmq4.NewSub(context.Background())

	url := p.activeNodes[blockChainName].NotifyURL
	err := sub.Dial(url)
	if err != nil {
		return sub, err
	}

	err = sub.SetOption(zmq4.OptionSubscribe, "hashblock")
	if err != nil {
		return sub, err
	}

	logErr := func(msg zmq4.Msg, err error) zmq4.Msg {
		if err != nil {
			log.Println(err)
		}

		return msg
	}

	go func() {
		for {
			msg := logErr(sub.Recv())

			if len(msg.Frames) > 2 {
				var blockHashCounter uint32
				blockHashCounter |= uint32(msg.Frames[2][0])
				blockHashCounter |= uint32(msg.Frames[2][1]) << 8
				blockHashCounter |= uint32(msg.Frames[2][2]) << 16
				blockHashCounter |= uint32(msg.Frames[2][3]) << 24

				hashBlockChannel <- hashBlockResponse{
					blockChainName:    blockChainName,
					previousBlockHash: hex.EncodeToString(msg.Frames[1]),
					blockHashCounter:  blockHashCounter,
				}
			}

		}
	}()

	return sub, nil
}

func (p *PoolServer) CheckAndRecoverRPCs() error {
	var err error
	for coin, manager := range p.rpcManagers {
		err = manager.CheckAndRecoverRPCs()
		if err != nil {
			coinError := errors.New(coin)
			return errors.Join(coinError, err)
		}
	}
	return nil
}
