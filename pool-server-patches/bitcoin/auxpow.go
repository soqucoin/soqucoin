package bitcoin

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

const (
	mergedMiningHeader = "fabe6d6d"
	// AuxMerkleSize is the number of leaves in the aux chain Merkle tree.
	// 32 is the minimum power-of-two where SOQ(0), DOGE(98), BEL(16) all get unique slots.
	AuxMerkleSize   = 32
	AuxMerkleHeight = 5 // log2(32)
	AuxMerkleNonce  = 0
)

type AuxBlock struct {
	Hash              string `json:"hash"`
	ChainID           int    `json:"chainid"`
	PreviousBlockHash string `json:"previousblockhash"`
	CoinbaseHash      string `json:"coinbasehash"`
	CoinbaseValue     uint   `json:"coinbasevalue"`
	Bits              string `json:"bits"`
	Height            uint64 `json:"height"`
	Target            string `json:"target"`
	UnderscoreTarget  string `json:"_target"` // BEL uses "_target" instead of "target"
}

// GetTarget returns the target string, handling BEL's _target field.
func (b *AuxBlock) GetTarget() string {
	if b.Target != "" {
		return b.Target
	}
	return b.UnderscoreTarget
}

// getExpectedIndex replicates auxpow.cpp::getExpectedIndex exactly.
// It computes the slot in the aux Merkle tree for a given chain ID.
// Consensus-critical: must match the C++ implementation in SOQ/DOGE/BEL daemons.
func getExpectedIndex(nNonce uint32, nChainId int, h uint) uint32 {
	rand := nNonce
	rand = rand*1103515245 + 12345
	rand += uint32(nChainId)
	rand = rand*1103515245 + 12345
	return rand % (1 << h)
}

// auxDoubleSha256 wraps the package-level doubleSha256Bytes and returns a slice.
func auxDoubleSha256(data []byte) []byte {
	result := doubleSha256Bytes(data)
	return result[:]
}

// AuxMerkleResult holds the tree root and per-chain branch proofs.
type AuxMerkleResult struct {
	MerkleRoot string            // 32-byte hex root to embed in coinbase
	Branches   map[int]AuxBranch // auxBlockIndex -> branch proof
	Slots      map[int]uint32    // auxBlockIndex -> slot in tree
}

// AuxBranch is the Merkle proof for one aux chain.
type AuxBranch struct {
	Hashes []string // branch hashes (hex), bottom-up, length = AuxMerkleHeight
	Mask   uint32   // bitmask indicating left/right at each level
}

// BuildAuxMerkleTree builds a 32-leaf Merkle tree from aux block hashes.
// Each chain is placed at its slot determined by getExpectedIndex.
// Empty slots are filled with zero hashes (32 zero bytes).
func BuildAuxMerkleTree(auxBlocks []AuxBlock) (*AuxMerkleResult, error) {
	// Initialize all 32 leaves with zero hash
	zeroHash := make([]byte, 32)
	leaves := make([][]byte, AuxMerkleSize)
	for i := range leaves {
		leaves[i] = make([]byte, 32)
		copy(leaves[i], zeroHash)
	}

	result := &AuxMerkleResult{
		Branches: make(map[int]AuxBranch),
		Slots:    make(map[int]uint32),
	}

	// Place each aux chain hash at its computed slot
	for i, ab := range auxBlocks {
		slot := getExpectedIndex(AuxMerkleNonce, ab.ChainID, AuxMerkleHeight)
		result.Slots[i] = slot

		// Decode the aux block hash from hex, reverse it (internal byte order)
		hashBytes, err := hex.DecodeString(ab.Hash)
		if err != nil {
			return nil, fmt.Errorf("invalid aux block hash for chain %d: %w", ab.ChainID, err)
		}
		// AuxPoW Merkle tree uses hashes in internal byte order (reversed from RPC display)
		reverseBytes(hashBytes)
		leaves[slot] = hashBytes

		log.Printf("[auxpow] Chain %d (chainid=%d) -> slot %d", i, ab.ChainID, slot)
	}

	// Build Merkle tree bottom-up, collecting branch proofs
	currentLevel := make([][]byte, len(leaves))
	copy(currentLevel, leaves)

	// Track branch hashes for each aux block
	branchData := make(map[int][]string)
	branchMasks := make(map[int]uint32)
	for i := range auxBlocks {
		branchData[i] = make([]string, 0, AuxMerkleHeight)
		branchMasks[i] = 0
	}

	// Current position of each chain in the tree
	positions := make(map[int]uint32)
	for i := range auxBlocks {
		positions[i] = result.Slots[i]
	}

	for level := uint(0); level < AuxMerkleHeight; level++ {
		nextLevel := make([][]byte, len(currentLevel)/2)

		for i := range auxBlocks {
			pos := positions[i]
			// Sibling is the other node in the pair
			var sibling uint32
			if pos%2 == 0 {
				sibling = pos + 1
				// pos is left child, mask bit = 0
			} else {
				sibling = pos - 1
				// pos is right child, mask bit = 1
				branchMasks[i] |= (1 << level)
			}
			branchData[i] = append(branchData[i], hex.EncodeToString(currentLevel[sibling]))
			positions[i] = pos / 2
		}

		// Compute next level
		for j := 0; j < len(currentLevel); j += 2 {
			combined := append(currentLevel[j], currentLevel[j+1]...)
			nextLevel[j/2] = auxDoubleSha256(combined)
		}
		currentLevel = nextLevel
	}

	// Root is the single remaining hash
	result.MerkleRoot = hex.EncodeToString(currentLevel[0])

	// Store branch proofs
	for i := range auxBlocks {
		result.Branches[i] = AuxBranch{
			Hashes: branchData[i],
			Mask:   branchMasks[i],
		}
	}

	return result, nil
}

// reverseHexString reverses the byte order of a hex string.
// e.g. "aabbccdd" -> "ddccbbaa"
// Used to convert Merkle roots from internal (LE) to display (BE) order
// for the coinbase commitment, matching soqucoind/dogecoind expectations.
func reverseHexString(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("reverseHexString: invalid hex: " + err.Error())
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return hex.EncodeToString(b)
}

// GetMultiAuxWork builds the merged mining commitment for the LTC coinbase.
// Format: fabe6d6d + <merkle_root> + <merkle_size_LE_u32> + <merkle_nonce_LE_u32>
func GetMultiAuxWork(auxBlocks []AuxBlock) (string, *AuxMerkleResult, error) {
	result, err := BuildAuxMerkleTree(auxBlocks)
	if err != nil {
		return "", nil, err
	}

	// Build the coinbase commitment
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, AuxMerkleSize)

	nonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(nonceBytes, AuxMerkleNonce)

	// CRITICAL: The Merkle root must be in display (big-endian) byte order
	// in the coinbase. soqucoind/dogecoind CAuxPow::check() computes the root
	// in internal order, then reverses it before searching the coinbase
	// (auxpow.cpp line 94: std::reverse(vchRootHash)).
	// Our BuildAuxMerkleTree produces the root in internal order, so we must
	// reverse it here to match.
	commitment := mergedMiningHeader +
		reverseHexString(result.MerkleRoot) +
		hex.EncodeToString(sizeBytes) +
		hex.EncodeToString(nonceBytes)

	return commitment, result, nil
}

// --- Single-chain backward compatibility (for existing SOQ-only operation) ---

// GetWork returns the merged mining commitment for a single aux chain.
// This is the legacy format: fabe6d6d + <hash> + 01000000 + 00000000
func (b *AuxBlock) GetWork() string {
	return mergedMiningHeader + b.Hash + "010000000000000000002632"
}

// --- AuxPoW proof construction ---

type AuxPow struct {
	ParentCoinbase   string
	ParentHeaderHash string
	ParentMerkleBranch
	auxMerkleBranch      AuxChainMerkleBranch
	ParentHeaderUnhashed string
}

// MakeAuxPow builds an AuxPoW proof for a single-aux-chain setup (legacy).
func MakeAuxPow(parentBlock BitcoinBlock) AuxPow {
	if parentBlock.hash == "" {
		panic("Set parent block hash first")
	}

	return AuxPow{
		ParentCoinbase:       parentBlock.coinbase,
		ParentHeaderHash:     parentBlock.hash,
		ParentMerkleBranch:   makeParentMerkleBranch(parentBlock.merkleSteps),
		auxMerkleBranch:      makeAuxChainMerkleBranchLegacy(),
		ParentHeaderUnhashed: parentBlock.header,
	}
}

// MakeAuxPowForChain builds an AuxPoW proof for a specific chain in a multi-aux tree.
// The proof includes the Merkle branch proving the chain's hash is at the correct slot.
func MakeAuxPowForChain(parentBlock BitcoinBlock, branch AuxBranch) AuxPow {
	if parentBlock.hash == "" {
		panic("Set parent block hash first")
	}

	return AuxPow{
		ParentCoinbase:       parentBlock.coinbase,
		ParentHeaderHash:     parentBlock.hash,
		ParentMerkleBranch:   makeParentMerkleBranch(parentBlock.merkleSteps),
		auxMerkleBranch:      makeAuxChainMerkleBranchMulti(branch),
		ParentHeaderUnhashed: parentBlock.header,
	}
}

func (p *AuxPow) Serialize() string {
	return p.ParentCoinbase +
		p.ParentHeaderHash +
		p.ParentMerkleBranch.Serialize() +
		p.auxMerkleBranch.Serialize() +
		p.ParentHeaderUnhashed
}

// --- Parent Merkle Branch (coinbase -> LTC block header) ---

type ParentMerkleBranch struct {
	Length uint
	Items  []string
	mask   string
}

func makeParentMerkleBranch(items []string) ParentMerkleBranch {
	length := uint(len(items))
	return ParentMerkleBranch{
		Length: length,
		Items:  items,
		mask:   "00000000",
	}
}

func (pm *ParentMerkleBranch) Serialize() string {
	items := ""
	for _, item := range pm.Items {
		items = items + item
	}
	return varUint(pm.Length) + items + pm.mask
}

// --- Aux Chain Merkle Branch (aux hash -> aux Merkle root) ---

type AuxChainMerkleBranch struct {
	numberOfBranches uint
	items            []string
	mask             string
}

// makeAuxChainMerkleBranchLegacy creates the branch for merkle_size=1 (single aux chain).
func makeAuxChainMerkleBranchLegacy() AuxChainMerkleBranch {
	return AuxChainMerkleBranch{
		numberOfBranches: 0,
		items:            nil,
		mask:             "00000000",
	}
}

// makeAuxChainMerkleBranchMulti creates the branch for a multi-aux-chain Merkle tree.
func makeAuxChainMerkleBranchMulti(branch AuxBranch) AuxChainMerkleBranch {
	maskBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(maskBytes, branch.Mask)

	return AuxChainMerkleBranch{
		numberOfBranches: uint(len(branch.Hashes)),
		items:            branch.Hashes,
		mask:             hex.EncodeToString(maskBytes),
	}
}

func (am *AuxChainMerkleBranch) Serialize() string {
	items := ""
	for _, item := range am.items {
		items = items + item
	}
	return varUint(am.numberOfBranches) + items + am.mask
}

// --- Utility ---

func reverseBytes(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func debugAuxPow(parentBlock BitcoinBlock, parentMerkle ParentMerkleBranch, auxchainMerkle AuxChainMerkleBranch) {
	fmt.Println()
	fmt.Println("coinbase", parentBlock.coinbase)
	fmt.Println("hash", parentBlock.hash)
	fmt.Println("merkleSteps", parentBlock.merkleSteps)
	fmt.Println("merkleDigested", parentMerkle.Serialize())
	fmt.Println("chainmerklebranch", auxchainMerkle.Serialize())
	fmt.Println("header", parentBlock.header)
	fmt.Println()
}
