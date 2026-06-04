package pool

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"designs.capital/dogepool/bitcoin"
	"designs.capital/dogepool/persistence"
)

func (p *PoolServer) fetchRpcBlockTemplatesAndCacheWork() error {
	primaryRPC := p.GetPrimaryNode().RPC
	const minPeers int64 = 1
	peerCount, err := primaryRPC.GetPeerCount()
	if err != nil {
		return fmt.Errorf("fork guard: GetPeerCount failed: %w", err)
	}
	if peerCount < minPeers {
		return fmt.Errorf("fork guard: only %d peers (minimum %d) — refusing to generate work", peerCount, minPeers)
	}

	// FORK GUARD Layer 4: Check cross-node chain tip verifier.
	if p.chainTipVerifier != nil && p.chainTipVerifier.IsHalted() {
		divergenceCount := p.chainTipVerifier.DivergenceCount()
		log.Printf("🚨 FORK GUARD Layer 4: CHAIN TIP DIVERGENCE HALT — refusing to generate work. "+
			"Local chain tip has diverged from verification peers for %d consecutive checks. "+
			"Manual intervention required: check node sync status, addnode config, and network connectivity.",
			divergenceCount)
		return fmt.Errorf("fork guard layer 4: chain tip divergence halt (divergent for %d checks)", divergenceCount)
	}

	// Check aux chain peer counts (warning only, don't block)
	for _, chainName := range p.config.BlockChainOrder.GetAuxChains() {
		if node, exists := p.activeNodes[chainName]; exists {
			auxPeers, auxErr := node.RPC.GetPeerCount()
			if auxErr != nil {
				log.Printf("⚠️  FORK GUARD: Cannot check peer count for %s: %v", chainName, auxErr)
			} else if auxPeers < minPeers {
				log.Printf("⚠️  FORK GUARD: %s has %d peers (minimum: %d) — aux blocks may be on an isolated fork",
					chainName, auxPeers, minPeers)
			}
		}
	}

	var block *bitcoin.BitcoinBlock
	template, auxBlocks, err := p.fetchAllBlockTemplatesFromRPC()
	if err != nil {
		// Switch nodes if we fail to get work
		err = p.CheckAndRecoverRPCs()
		if err != nil {
			return err
		}
		template, auxBlocks, err = p.fetchAllBlockTemplatesFromRPC()
		if err != nil {
			return err
		}
	}

	auxillary := p.config.BlockSignature

	if len(auxBlocks) > 0 {
		// Multi-aux: build Merkle tree of all aux chain hashes
		mergedPOW, merkleResult, merr := bitcoin.GetMultiAuxWork(auxBlocks)
		if merr != nil {
			log.Printf("[multi-aux] ❌ Failed to build Merkle tree: %v — falling back to no aux", merr)
		} else {
			auxillary = auxillary + hexStringToByteString(mergedPOW)
			p.templates.AuxBlocks = auxBlocks
			p.templates.AuxMerkle = merkleResult
		}
	} else {
		p.templates.AuxBlocks = nil
		p.templates.AuxMerkle = nil
	}

	primaryName := p.config.GetPrimary()
	rewardPubScriptKey := p.GetPrimaryNode().RewardPubScriptKey
	extranonceByteReservationLength := 12

	block, p.workCache, err = bitcoin.GenerateWork(&template, nil,
		primaryName, auxillary, rewardPubScriptKey,
		extranonceByteReservationLength)
	if err != nil {
		log.Print(err)
	}

	p.templates.BitcoinBlock = *block

	return nil
}

// Main OUTPUT
func (p *PoolServer) recieveWorkFromClient(share bitcoin.Work, client *stratumClient) error {
	primaryBlockTemplate := p.templates.GetPrimary()
	if primaryBlockTemplate.Template == nil {
		return errors.New("primary block template not yet set")
	}
	auxBlocks := p.templates.AuxBlocks

	var err error

	workerString := share[0].(string)
	workerStringParts := strings.Split(workerString, ".")
	if len(workerStringParts) < 2 {
		return errors.New("invalid miner address")
	}
	minerAddress := workerStringParts[0]
	rigID := workerStringParts[1]

	primaryBlockHeight := primaryBlockTemplate.Template.Height
	nonce := share[primaryBlockTemplate.NonceSubmissionSlot()].(string)
	extranonce2Slot, _ := primaryBlockTemplate.Extranonce2SubmissionSlot()
	extranonce2 := share[extranonce2Slot].(string)
	nonceTime := share[primaryBlockTemplate.NonceTimeSubmissionSlot()].(string)

	extranonce := client.extranonce1 + extranonce2

	_, err = primaryBlockTemplate.MakeHeader(extranonce, nonce, nonceTime)
	if err != nil {
		return err
	}

	// Fallback: if client difficulty not yet set, use pool default
	if client.difficulty == 0 {
		client.difficulty = p.config.PoolDifficulty
	}

	// Multi-target share validation: check primary AND all aux chain targets
	shareStatus, shareDifficulty, candidateAuxIndices := validateAndWeighShare(
		&primaryBlockTemplate, auxBlocks, client.difficulty)

	// Build height message
	heightMessage := fmt.Sprintf("%v", primaryBlockHeight)
	if len(candidateAuxIndices) > 0 {
		for _, idx := range candidateAuxIndices {
			heightMessage += fmt.Sprintf(",%v", auxBlocks[idx].Height)
		}
	}

	if shareStatus == shareInvalid {
		m := "❔ Invalid share for block %v from %v [%v] [%v]"
		m = fmt.Sprintf(m, heightMessage, client.ip, rigID, client.userAgent)
		return errors.New(m)
	}

	m := "Valid share for block %v from %v [%v]"
	m = fmt.Sprintf(m, heightMessage, client.ip, rigID)
	log.Println(m)

	blockTarget := bitcoin.Target(primaryBlockTemplate.Template.Target)
	blockDifficulty, _ := blockTarget.ToDifficulty()
	blockDifficulty = blockDifficulty * primaryBlockTemplate.ShareMultiplier()

	p.Lock()
	p.shareBuffer = append(p.shareBuffer, persistence.Share{
		PoolID:            p.config.PoolName,
		BlockHeight:       primaryBlockHeight,
		Miner:             minerAddress,
		Worker:            rigID,
		UserAgent:         client.userAgent,
		Difficulty:        shareDifficulty,
		NetworkDifficulty: blockDifficulty,
		IpAddress:         client.ip,
		Created:           time.Now(),
	})
	p.Unlock()

	// Vardiff
	if client.vardiff != nil {
		client.vardiff.recordShare()
		retargetClient(client)
	}

	if shareStatus == shareValid {
		return nil
	}

	successStatus := 0

	// Submit to ALL aux chains whose target was beaten
	if len(candidateAuxIndices) > 0 {
		for _, idx := range candidateAuxIndices {
			aux := auxBlocks[idx]
			chainName := p.config.BlockChainOrder[idx+1] // +1 because [0] is primary

			log.Printf("🎉 %s block candidate at height %d from %v [%v]", chainName, aux.Height, client.ip, rigID)

			err = p.submitAuxBlockMulti(primaryBlockTemplate, aux, idx)
			if err != nil {
				log.Printf("⚠️  %s aux block submit failed: %v — will persist as pending", chainName, err)
			}

			// Record the found block
			auxTarget := bitcoin.Target(reverseHexBytes(aux.GetTarget()))
			auxDifficulty, _ := auxTarget.ToDifficulty()
			auxDifficulty = auxDifficulty * bitcoin.GetChain(chainName).ShareMultiplier()

			found := persistence.Found{
				PoolID:                      p.config.PoolName,
				Status:                      persistence.StatusPending,
				Type:                        chainName,
				ConfirmationProgress:        0,
				Miner:                       minerAddress,
				Chain:                       chainName,
				Created:                     time.Now(),
				Hash:                        aux.Hash,
				NetworkDifficulty:           auxDifficulty,
				BlockHeight:                 uint(aux.Height),
				TransactionConfirmationData: reverseHexBytes(aux.CoinbaseHash),
			}
			if insertErr := persistence.Blocks.Insert(found); insertErr != nil {
				log.Println(insertErr)
			}

			successStatus = aux1Candidate // at least one aux was found
		}
	}

	// Submit primary (LTC) if it beats the primary target
	if shareStatus == primaryCandidate || shareStatus == dualCandidate {
		err = p.submitBlockToChain(primaryBlockTemplate)
		if err != nil {
			// Try to submit on different node
			err = p.rpcManagers[p.config.GetPrimary()].CheckAndRecoverRPCs()
			if err != nil {
				return err
			}
			err = p.submitBlockToChain(primaryBlockTemplate)
		}

		if err != nil {
			return err
		} else {
			found := persistence.Found{
				PoolID:               p.config.PoolName,
				Status:               persistence.StatusPending,
				Type:                 "Primary",
				ConfirmationProgress: 0,
				Miner:                minerAddress,
				Chain:                p.config.GetPrimary(),
				Created:              time.Now(),
				NetworkDifficulty:    blockDifficulty,
				BlockHeight:          primaryBlockHeight,
			}
			found.Hash, err = primaryBlockTemplate.HeaderHashed()
			if err != nil {
				log.Println(err)
			}
			found.TransactionConfirmationData, err = primaryBlockTemplate.CoinbaseHashed()
			if err != nil {
				log.Println(err)
			}

			if insertErr := persistence.Blocks.Insert(found); insertErr != nil {
				log.Println(insertErr)
			}
			if successStatus == aux1Candidate {
				successStatus = dualCandidate
			} else {
				successStatus = primaryCandidate
			}
		}
	}

	statusReadable := statusMap[successStatus]
	log.Printf("✅  Successful %v submission of block %v from: %v [%v]", statusReadable, heightMessage, client.ip, rigID)

	return nil
}

func (pool *PoolServer) generateWorkFromCache(refresh bool) (bitcoin.Work, error) {
	work := append(pool.workCache, interface{}(refresh))

	return work, nil
}
