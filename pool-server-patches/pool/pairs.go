package pool

import "designs.capital/dogepool/bitcoin"

type Pair struct {
	bitcoin.BitcoinBlock
	AuxBlocks []bitcoin.AuxBlock
	AuxMerkle *bitcoin.AuxMerkleResult // Multi-aux Merkle tree result (branches + slots)
}

func (p Pair) GetPrimary() bitcoin.BitcoinBlock {
	return p.BitcoinBlock
}

func (p Pair) GetAuxN(n int) *bitcoin.AuxBlock {
	if n >= len(p.AuxBlocks) {
		return nil
	}
	return &p.AuxBlocks[n]
}

func (p Pair) GetAux1() *bitcoin.AuxBlock {
	return p.GetAuxN(0)
}
