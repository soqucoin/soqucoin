// Package persistence provides a no-op persistence layer for solo mining.
// Instead of PostgreSQL, shares and found blocks are logged to console.
// This eliminates the database dependency for solo miners.
package persistence

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"designs.capital/dogepool/config"
)

const (
	StatusPending   = "pending"
	StatusOrphaned  = "orphaned"
	StatusConfirmed = "confirmed"
)

// Share represents a submitted share from a miner
type Share struct {
	PoolID            string
	BlockHeight       uint
	Miner             string
	Worker            string
	UserAgent         string
	Difficulty        float64
	NetworkDifficulty float64
	IpAddress         string
	Created           time.Time
}

// Found represents a found block
type Found struct {
	ID                          uint
	PoolID                      string
	Chain                       string
	BlockHeight                 uint
	NetworkDifficulty           float64
	Status                      string
	Type                        string
	ConfirmationProgress        float32
	Effort                      float64
	TransactionConfirmationData string
	Miner                       string
	Worker                      string
	Reward                      float64
	Source                      string
	Hash                        string
	Created                     time.Time
}

type FoundBlocks []Found

func (b *FoundBlocks) GetConfirmed() FoundBlocks {
	var confirmed FoundBlocks
	for _, block := range *b {
		if block.Status == StatusConfirmed {
			confirmed = append(confirmed, block)
		}
	}
	return confirmed
}

// ShareRepository logs shares to console (no-op for solo mining)
type ShareRepository struct {
	mu         sync.Mutex
	totalCount int64
	logFile    *os.File
}

// FoundRepository logs found blocks to a JSON file
type FoundRepository struct {
	mu      sync.Mutex
	logFile *os.File
}

// Global repository instances (compatible with pool code's expectations)
var (
	Shares   ShareRepository
	Blocks   FoundRepository
	Balances struct{} // unused in solo mode
	Miners   struct{} // unused in solo mode
	Payments struct{} // unused in solo mode
	Pool     struct{} // unused in solo mode
)

// MakePersister initializes file-based logging (no database)
func MakePersister(configuration *config.Config) error {
	// Open blocks log file
	f, err := os.OpenFile("found_blocks.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open found_blocks.json: %w", err)
	}
	Blocks.logFile = f

	log.Println("📋 Solo miner persistence: logging to console + found_blocks.json")
	return nil
}

// InsertBatch logs shares to console (no database write)
func (r *ShareRepository) InsertBatch(shares []Share) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.totalCount += int64(len(shares))
	// Only log count, not every share (would be too noisy)
	return nil
}

// Insert logs a found block to the JSON log file
func (r *FoundRepository) Insert(found Found) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	log.Printf("🎉 BLOCK FOUND! Chain=%s Height=%d Hash=%s Miner=%s Worker=%s",
		found.Chain, found.BlockHeight, found.Hash, found.Miner, found.Worker)

	entry, err := json.Marshal(found)
	if err != nil {
		return err
	}

	if r.logFile != nil {
		r.logFile.Write(entry)
		r.logFile.Write([]byte("\n"))
		r.logFile.Sync()
	}

	return nil
}
