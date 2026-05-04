package bitcoin

// TransactionOut serializes a single CTxOut for the Soqucoin wire format.
// Soqucoin CTxOut = nValue(8B) + scriptPubKey(varint+bytes) + nVisibility(1B) + nAssetType(1B)
func TransactionOut(amount, pubScriptKey string) string {
	lengthBytes := uint(len(pubScriptKey) / 2)
	return amount + varUint(lengthBytes) + pubScriptKey + "00" + "00"
}
