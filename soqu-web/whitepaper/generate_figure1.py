#!/usr/bin/env python3
"""
Generate a professional architecture diagram for Soqucoin whitepaper Figure 1.
Uses matplotlib with clean, professional styling.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

# Set up the figure with professional styling
fig, ax = plt.subplots(1, 1, figsize=(14, 11))
ax.set_xlim(0, 14)
ax.set_ylim(0, 11)
ax.set_aspect('equal')
ax.axis('off')
fig.patch.set_facecolor('white')

# Color palette - colors match the legend
colors = {
    'tx_structure': '#E3F2FD',      # Light blue (Step 1)
    'tx_border': '#1976D2',         # Blue
    'pat': '#C8E6C9',               # Light green (Step 2a - PAT)
    'pat_border': '#388E3C',        # Green
    'bulletproofs': '#FFECB3',      # Light amber (Step 2b - Bulletproofs++)
    'bp_border': '#F57C00',         # Orange
    'latticefold': '#E1BEE7',       # Light purple (Step 3)
    'lf_border': '#7B1FA2',         # Purple
    'binius': '#F3E5F5',            # Lighter purple for inner Binius section
    'binius_border': '#9C27B0',     # Medium purple
    'block': '#ECEFF1',             # Light gray (Step 4)
    'block_border': '#455A64',      # Blue gray
    'arrow': '#37474F',             # Dark gray
    'text': '#000000',              # BLACK for all text
}

# Font settings - ALL BLACK TEXT
title_font = {'family': 'sans-serif', 'weight': 'bold', 'size': 16, 'color': '#000000'}
header_font = {'family': 'sans-serif', 'weight': 'bold', 'size': 11, 'color': '#000000'}
body_font = {'family': 'sans-serif', 'size': 9, 'color': '#000000'}
small_font = {'family': 'sans-serif', 'size': 8, 'color': '#000000'}

def draw_box(ax, x, y, w, h, fill_color, border_color, label, sublabels=None, corner_radius=0.15):
    """Draw a rounded rectangle with label."""
    box = FancyBboxPatch((x, y), w, h, 
                          boxstyle=f"round,pad=0.02,rounding_size={corner_radius}",
                          facecolor=fill_color, edgecolor=border_color, linewidth=2.5)
    ax.add_patch(box)
    
    # Add header - BLACK text
    ax.text(x + w/2, y + h - 0.35, label, ha='center', va='top', 
            fontdict=header_font)
    
    # Add sublabels - BLACK text
    if sublabels:
        for i, sublabel in enumerate(sublabels):
            ax.text(x + w/2, y + h - 0.8 - i*0.4, sublabel, ha='center', va='top',
                    fontdict=small_font)
    
    return box

def draw_inner_box(ax, x, y, w, h, fill_color, border_color, label, sublabels=None, corner_radius=0.1):
    """Draw an inner segment box."""
    box = FancyBboxPatch((x, y), w, h, 
                          boxstyle=f"round,pad=0.01,rounding_size={corner_radius}",
                          facecolor=fill_color, edgecolor=border_color, linewidth=1.5)
    ax.add_patch(box)
    
    # Add header - BLACK text
    ax.text(x + w/2, y + h - 0.25, label, ha='center', va='top', 
            fontdict={'family': 'sans-serif', 'weight': 'bold', 'size': 9, 'color': '#000000'})
    
    # Add sublabels - BLACK text
    if sublabels:
        for i, sublabel in enumerate(sublabels):
            ax.text(x + w/2, y + h - 0.55 - i*0.3, sublabel, ha='center', va='top',
                    fontdict={'family': 'sans-serif', 'size': 7, 'color': '#000000'})
    
    return box

def draw_arrow(ax, start, end):
    """Draw a straight arrow between two points."""
    arrow = FancyArrowPatch(start, end,
                            connectionstyle="arc3,rad=0",
                            arrowstyle='-|>',
                            mutation_scale=18,
                            color=colors['arrow'],
                            linewidth=2)
    ax.add_patch(arrow)

# Title
ax.text(7, 10.5, 'Soqucoin System Architecture', ha='center', va='center', fontdict=title_font)

# ============ Layer 1: Transaction Structure (BLUE - Step 1) ============
tx_x, tx_y, tx_w, tx_h = 0.3, 5.0, 2.8, 4.5
draw_box(ax, tx_x, tx_y, tx_w, tx_h, colors['tx_structure'], colors['tx_border'],
         'Transaction Structure',
         ['', 'Dilithium Signature', '(ML-DSA-44, 2421 B)', '',
          'Pedersen Commitment', '(33 B compressed)', '',
          'UTXO Inputs', '(PrevOut Refs)'])

# ============ Layer 2a: PAT Aggregation (GREEN - Step 2a) ============
pat_x, pat_y, pat_w, pat_h = 4.2, 7.5, 2.8, 2.0
draw_box(ax, pat_x, pat_y, pat_w, pat_h, colors['pat'], colors['pat_border'],
         'PAT Aggregation',
         ['Merkle Tree', '(64-72 B root)'])

# ============ Layer 2b: Bulletproofs++ (ORANGE/AMBER - Step 2b) ============
bp_x, bp_y, bp_w, bp_h = 4.2, 5.0, 2.8, 2.0
draw_box(ax, bp_x, bp_y, bp_w, bp_h, colors['bulletproofs'], colors['bp_border'],
         'Bulletproofs++',
         ['Range Proof', '(675 B)'])

# ============ Layer 3: LatticeFold+ Prover with Binius64 inside (PURPLE - Step 3) ============
# Larger container that includes Binius64 as inner segment
lf_x, lf_y, lf_w, lf_h = 7.8, 5.0, 3.2, 4.5
draw_box(ax, lf_x, lf_y, lf_w, lf_h, colors['latticefold'], colors['lf_border'],
         'LatticeFold+ Prover',
         ['', 'Recursive Folding', '(~1.38 KB proof)'])

# Inner Binius64 segment within LatticeFold+
binius_x, binius_y, binius_w, binius_h = lf_x + 0.2, lf_y + 0.3, lf_w - 0.4, 1.8
draw_inner_box(ax, binius_x, binius_y, binius_w, binius_h, colors['binius'], colors['binius_border'],
               'Binius64 Field',
               ['AVX2/GFNI Arithmetic', '(5 cycles/mul)'])

# ============ Layer 4: Block Structure (GRAY - Step 4) ============
blk_x, blk_y, blk_w, blk_h = 11.5, 4.8, 2.3, 4.9
draw_box(ax, blk_x, blk_y, blk_w, blk_h, colors['block'], colors['block_border'],
         'Block Structure',
         ['', 'Header', '(Merkle Root)', '',
          'LatticeFold+', 'Proof (1.38 KB)', '',
          'Bulletproofs++', 'Range Proofs', '',
          'Coinbase TX'])

# ============ Arrows - ALL STRAIGHT, NO OVERLAPS ============
# TX Structure -> PAT (horizontal at top)
draw_arrow(ax, (tx_x + tx_w, 8.5), (pat_x, 8.5))

# TX Structure -> Bulletproofs (horizontal at bottom)
draw_arrow(ax, (tx_x + tx_w, 6.0), (bp_x, 6.0))

# PAT -> LatticeFold (horizontal, aligned at top)
draw_arrow(ax, (pat_x + pat_w, 8.5), (lf_x, 8.5))

# LatticeFold -> Block (horizontal at top)
draw_arrow(ax, (lf_x + lf_w, 8.5), (blk_x, 8.5))

# Bulletproofs -> Block (horizontal at bottom, goes under LatticeFold box)
# Arrow at y=6.0 which is at the bottom of the LatticeFold box, not overlapping
draw_arrow(ax, (bp_x + bp_w, 6.0), (blk_x, 6.0))

# ============ Process Flow Legend - colored boxes match diagram ============
legend_y = 2.0
ax.text(0.3, legend_y + 1.8, 'Process Flow:', fontdict=header_font)

steps = [
    (colors['tx_structure'], colors['tx_border'], '1', 'Transaction Generation: User creates TX with Dilithium signatures and Pedersen commitments'),
    (colors['pat'], colors['pat_border'], '2a', 'PAT Aggregation: Signatures batched into Merkle-tree commitment'),
    (colors['bulletproofs'], colors['bp_border'], '2b', 'Bulletproofs++: Range proofs verify confidential amounts (675 B, 0.89 ms)'),
    (colors['latticefold'], colors['lf_border'], '3', 'LatticeFold+: PAT commitment folded into succinct proof via Binius64 field'),
    (colors['block'], colors['block_border'], '4', 'Block Assembly: Header commits to TXs; includes LF+ proof and BP++ range proofs'),
]

for i, (fill, border, num, text) in enumerate(steps):
    y_pos = legend_y + 1.2 - i * 0.5
    # Draw colored rectangle
    rect = FancyBboxPatch((0.3, y_pos - 0.15), 0.5, 0.3, 
                           boxstyle="round,pad=0.02,rounding_size=0.05",
                           facecolor=fill, edgecolor=border, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(0.55, y_pos, num, ha='center', va='center', color='#000000', fontweight='bold', fontsize=9)
    ax.text(0.95, y_pos, text, ha='left', va='center', fontdict=body_font)

# ============ Technical Notes - BLACK text ============
notes_x = 8.5
ax.text(notes_x, 3.5, 'Verification Complexity:', fontdict=header_font)
ax.text(notes_x, 3.0, '• OP_CHECKFOLDPROOF: O(1) verification', fontdict=small_font)
ax.text(notes_x, 2.6, '• Binius64: AVX2/GFNI field arithmetic (~5 cycles/mul)', fontdict=small_font)
ax.text(notes_x, 2.2, '• Soundness error: < 2^-130 (Theorem 4.2)', fontdict=small_font)
ax.text(notes_x, 1.8, '• Proof size: constant ~1.38 KB for any batch size', fontdict=small_font)
ax.text(notes_x, 1.4, '• Bulletproofs++: 675 B range proof, 0.89 ms verify', fontdict=small_font)

# Save
plt.tight_layout()
plt.savefig('paper_plots/architecture.png', dpi=300, bbox_inches='tight', 
            facecolor='white', edgecolor='none')
plt.savefig('paper_plots/figure1_architecture.png', dpi=300, bbox_inches='tight',
            facecolor='white', edgecolor='none')
print("Figure 1 saved to paper_plots/architecture.png")
