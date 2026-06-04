package pool

import (
	"designs.capital/dogepool/bitcoin"
)

const (
	shareInvalid = iota
	shareValid
	primaryCandidate
	aux1Candidate
	dualCandidate
)

var statusMap = map[int]string{
	2: "Primary",
	3: "Aux",
	4: "Dual",
}

// validateAndWeighShare checks the share hash against the primary target and ALL aux chain targets.
// Returns: status, share difficulty, and indices of aux chains whose target was beaten.
func validateAndWeighShare(primary *bitcoin.BitcoinBlock, auxBlocks []bitcoin.AuxBlock, poolDifficulty float64) (int, float64, []int) {
	primarySum, err := primary.Sum()
	logOnError(err)

	primaryTarget := bitcoin.Target(primary.Template.Target)
	primaryTargetBig, _ := primaryTarget.ToBig()

	poolTarget, _ := bitcoin.TargetFromDifficulty(poolDifficulty / primary.ShareMultiplier())
	shareDifficulty, _ := poolTarget.ToDifficulty()

	status := shareInvalid
	var candidateAuxIndices []int

	// Check primary target
	if primarySum.Cmp(primaryTargetBig) <= 0 {
		status = primaryCandidate
	}

	// Check ALL aux chain targets
	for i, aux := range auxBlocks {
		if aux.Hash == "" || aux.GetTarget() == "" {
			continue
		}
		auxTarget := bitcoin.Target(reverseHexBytes(aux.GetTarget()))
		auxTargetBig, _ := auxTarget.ToBig()

		if primarySum.Cmp(auxTargetBig) <= 0 {
			candidateAuxIndices = append(candidateAuxIndices, i)
		}
	}

	// Determine composite status
	if len(candidateAuxIndices) > 0 {
		if status == primaryCandidate {
			status = dualCandidate
		} else {
			status = aux1Candidate
		}
	}

	if status > shareInvalid {
		return status, shareDifficulty, candidateAuxIndices
	}

	// Check pool difficulty threshold
	poolTargetBig, _ := poolTarget.ToBig()
	if primarySum.Cmp(poolTargetBig) <= 0 {
		return shareValid, shareDifficulty, nil
	}

	return shareInvalid, shareDifficulty, nil
}
