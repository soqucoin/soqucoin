import matplotlib.pyplot as plt
import matplotlib.patches as patches

def create_architecture_diagram():
    # Adjusted Layout - Wider and cleaner
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8)
    ax.axis('off')

    # Style settings
    box_props = dict(boxstyle='round,pad=0.5', facecolor='#f8f9fa', edgecolor='#2c3e50', linewidth=2)
    highlight_props = dict(boxstyle='round,pad=0.5', facecolor='#e8f6f3', edgecolor='#16a085', linewidth=2)
    arrow_props = dict(arrowstyle='->', color='#34495e', lw=2, mutation_scale=20)
    text_props = dict(ha='center', va='center', fontsize=10, fontfamily='sans-serif')
    title_props = dict(ha='center', va='center', fontsize=12, fontweight='bold', color='#2c3e50')

    # 1. Wallets / Transactions Layer (Left)
    ax.text(2, 7.5, "1. Transaction Layer", **title_props)
    
    # Tx Boxes
    for i, y in enumerate([6.5, 5.5, 4.5]):
        rect = patches.FancyBboxPatch((0.5, y), 3, 0.8, boxstyle='round,pad=0.1', 
                                    facecolor='#ffffff', edgecolor='#bdc3c7')
        ax.add_patch(rect)
        ax.text(2, y+0.4, f"Transaction {i+1}\n(Dilithium Sig)", **text_props)

    # 2. PAT Commitment Layer (Center-Left)
    ax.text(6, 7.5, "2. PAT Commitment", **title_props)
    
    # Merkle Tree visual - Lines converging to PAT box
    # From Tx1 (y=6.9) to PAT input (y=6.2)
    ax.plot([3.5, 5], [6.9, 6.2], color='#95a5a6', lw=1.5, zorder=0)
    # From Tx2 (y=5.9) to PAT input (y=6.0)
    ax.plot([3.5, 5], [5.9, 6.0], color='#95a5a6', lw=1.5, zorder=0)
    # From Tx3 (y=4.9) to PAT input (y=5.8)
    ax.plot([3.5, 5], [4.9, 5.8], color='#95a5a6', lw=1.5, zorder=0)
    
    pat_box = patches.FancyBboxPatch((5, 5.5), 2, 1, **highlight_props)
    ax.add_patch(pat_box)
    ax.text(6, 6, "PAT\nCommitment", **text_props)

    # Arrow to Prover
    ax.annotate("", xy=(8.5, 6), xytext=(7, 6), arrowprops=arrow_props)

    # 3. Consensus Layer (Center-Right)
    ax.text(10, 7.5, "3. Consensus (Mining)", **title_props)
    
    prover_box = patches.FancyBboxPatch((8.5, 5.5), 3, 1, **highlight_props)
    ax.add_patch(prover_box)
    ax.text(10, 6, "LatticeFold+\nProver", **text_props)
    
    # Arrow down to Block
    ax.annotate("", xy=(10, 4.5), xytext=(10, 5.5), arrowprops=arrow_props)

    # PoW Box
    pow_box = patches.FancyBboxPatch((8.5, 3.5), 3, 0.8, boxstyle='round,pad=0.1', 
                                   facecolor='#fdf2e9', edgecolor='#d35400')
    ax.add_patch(pow_box)
    ax.text(10, 3.9, "Scrypt PoW\n(Miner)", **text_props)

    # 4. Blockchain Layer (Bottom Right)
    ax.text(10, 2.5, "4. On-Chain Storage", **title_props)
    
    # Shifted Block to right to avoid overlap with Layer 5
    block_box = patches.FancyBboxPatch((8, 0.5), 4, 1.5, boxstyle='round,pad=0.2', 
                                     facecolor='#ecf0f1', edgecolor='#2c3e50', lw=3)
    ax.add_patch(block_box)
    
    # Block contents
    ax.text(10, 1.25, "Soqucoin Block", fontsize=11, fontweight='bold')
    
    # Header
    header_rect = patches.Rectangle((8.2, 0.7), 1, 0.4, facecolor='#bdc3c7', edgecolor='none')
    ax.add_patch(header_rect)
    ax.text(8.7, 0.9, "Header", fontsize=8, ha='center')
    
    # Proof
    proof_rect = patches.Rectangle((9.3, 0.7), 1.2, 0.4, facecolor='#16a085', alpha=0.3, edgecolor='#16a085')
    ax.add_patch(proof_rect)
    ax.text(9.9, 0.9, "LatticeFold+\nProof", fontsize=8, ha='center', color='#0e6655')
    
    # Merkle Root
    root_rect = patches.Rectangle((10.6, 0.7), 1.2, 0.4, facecolor='#d35400', alpha=0.3, edgecolor='#d35400')
    ax.add_patch(root_rect)
    ax.text(11.2, 0.9, "PAT Root", fontsize=8, ha='center', color='#a04000')

    # 5. Verification (Bottom Left) - Moved far left to avoid overlap
    ax.text(3, 2.5, "5. Verification", **title_props)
    
    verify_box = patches.FancyBboxPatch((1.5, 0.5), 3, 1, **box_props)
    ax.add_patch(verify_box)
    ax.text(3, 1, "Node Verifier\nOP_CHECKFOLDPROOF\n(0.68ms)", **text_props)
    
    # Arrow from Block to Verifier (Long arrow right to left)
    # Path: Block -> Down -> Left -> Up -> Verifier
    ax.annotate("", xy=(4.5, 1), xytext=(8, 1), arrowprops=dict(arrowstyle='<-', color='#34495e', lw=2, linestyle='--'))
    ax.text(6.25, 1.2, "Sync / Propagate", fontsize=9, color='#34495e', ha='center')

    # Connecting lines
    # From PAT to Block (Merkle Root) - Curve around
    # Draw a line from PAT box right side, down to Block
    # Actually, PAT root goes into Block Header.
    # Let's draw a line from PAT box to Block
    
    # Path: PAT(6, 5.5) -> (7.5, 5.5) -> (7.5, 2) -> (11.2, 2) -> (11.2, 1.1)
    # Simplified: PAT -> Prover -> Block (Logical flow)
    # But PAT Root also goes directly to block header logically.
    # Let's just keep the Prover flow as the main one, and maybe a dotted line for "Root"
    
    ax.plot([7, 7.5, 7.5, 11.2, 11.2], [6, 6, 2, 2, 1.1], color='#d35400', lw=1, linestyle=':', zorder=0)
    ax.text(7.6, 4, "Merkle Root", fontsize=8, color='#d35400', rotation=90)

    plt.tight_layout()
    plt.savefig('soqu-web/images/architecture.png', dpi=300, bbox_inches='tight')
    plt.savefig('soqu-web/whitepaper/paper_plots/architecture.png', dpi=300, bbox_inches='tight')
    print("Architecture diagram generated.")

if __name__ == "__main__":
    create_architecture_diagram()
