#!/usr/bin/env python3
"""
Generate a professional, symmetric architecture diagram for Soqucoin.
Flow verified against source code (interpreter.cpp, rpcwallet.cpp).
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle

# Figure setup - clean grid layout
fig, ax = plt.subplots(1, 1, figsize=(14, 10))
ax.set_xlim(0, 14)
ax.set_ylim(0, 10)
ax.set_aspect('equal')
ax.axis('off')
fig.patch.set_facecolor('white')

# Professional color palette
colors = {
    'blue': '#E3F2FD',
    'blue_border': '#1565C0',
    'green': '#E8F5E9', 
    'green_border': '#2E7D32',
    'amber': '#FFF8E1',
    'amber_border': '#FF8F00',
    'purple': '#F3E5F5',
    'purple_border': '#7B1FA2',
    'gray': '#ECEFF1',
    'gray_border': '#455A64',
    'teal': '#E0F2F1',
    'teal_border': '#00796B',
    'arrow': '#37474F',
    'text': '#212121',
}

# Font settings - strong, dark, readable
title_font = {'family': 'sans-serif', 'weight': 'bold', 'size': 16, 'color': colors['text']}
header_font = {'family': 'sans-serif', 'weight': 'bold', 'size': 11, 'color': colors['text']}
body_font = {'family': 'sans-serif', 'weight': 'medium', 'size': 9, 'color': colors['text']}
small_font = {'family': 'sans-serif', 'size': 8, 'color': '#424242'}

def draw_box(ax, x, y, w, h, fill, border):
    box = FancyBboxPatch((x, y), w, h, 
                          boxstyle="round,pad=0.02,rounding_size=0.12",
                          facecolor=fill, edgecolor=border, linewidth=2.5)
    ax.add_patch(box)

def draw_arrow_h(ax, x1, x2, y):
    """Horizontal arrow"""
    ax.annotate('', xy=(x2, y), xytext=(x1, y),
                arrowprops=dict(arrowstyle='-|>', color=colors['arrow'], lw=2))

def draw_arrow_v(ax, x, y1, y2):
    """Vertical arrow"""
    ax.annotate('', xy=(x, y2), xytext=(x, y1),
                arrowprops=dict(arrowstyle='-|>', color=colors['arrow'], lw=2))

def draw_step(ax, x, y, num, color):
    """Step number badge"""
    circle = Circle((x, y), 0.22, facecolor=color, edgecolor='white', linewidth=2, zorder=10)
    ax.add_patch(circle)
    ax.text(x, y, num, ha='center', va='center', fontweight='bold', fontsize=10, color='white', zorder=11)

# ============ TITLE ============
ax.text(7, 9.5, 'Soqucoin System Architecture', ha='center', fontdict=title_font)

# ============ GRID LAYOUT (4 columns x 2 rows) ============
# Column positions: 0.5, 4.0, 7.5, 11.0
# Row positions: Top=7.0, Bottom=3.5

col = [0.8, 4.0, 7.2, 10.4]  # x positions
row = [6.5, 3.0]              # y positions (top, bottom)
box_w, box_h = 2.8, 2.2       # standard box size

# ============ ROW 1: Transaction Flow ============

# [1] User Wallet
draw_step(ax, col[0], 8.9, '1', colors['blue_border'])
draw_box(ax, col[0], row[0], box_w, box_h, colors['blue'], colors['blue_border'])
ax.text(col[0]+box_w/2, row[0]+1.9, 'User Wallet', ha='center', fontdict=header_font)
ax.text(col[0]+box_w/2, row[0]+1.4, 'Dilithium Keypair', ha='center', fontdict=body_font)
ax.text(col[0]+box_w/2, row[0]+1.0, '(ML-DSA-44)', ha='center', fontdict=small_font)
ax.text(col[0]+box_w/2, row[0]+0.5, 'sk: 2,560 B', ha='center', fontdict=small_font)
ax.text(col[0]+box_w/2, row[0]+0.2, 'pk: 1,312 B', ha='center', fontdict=small_font)

# [2a] Standard TX
draw_step(ax, col[1], 8.9, '2a', colors['green_border'])
draw_box(ax, col[1], row[0], box_w, box_h, colors['green'], colors['green_border'])
ax.text(col[1]+box_w/2, row[0]+1.9, 'Standard TX', ha='center', fontdict=header_font)
ax.text(col[1]+box_w/2, row[0]+1.4, 'Dilithium Signature', ha='center', fontdict=body_font)
ax.text(col[1]+box_w/2, row[0]+1.0, '2,421 bytes', ha='center', fontdict=small_font)
ax.text(col[1]+box_w/2, row[0]+0.5, 'Witness: sig + pk', ha='center', fontdict=small_font)

# [2b] Confidential TX  
draw_step(ax, col[1], row[1]+2.4, '2b', colors['amber_border'])
draw_box(ax, col[1], row[1], box_w, box_h, colors['amber'], colors['amber_border'])
ax.text(col[1]+box_w/2, row[1]+1.9, 'Confidential TX', ha='center', fontdict=header_font)
ax.text(col[1]+box_w/2, row[1]+1.4, 'Pedersen + BP++', ha='center', fontdict=body_font)
ax.text(col[1]+box_w/2, row[1]+1.0, 'Commitment: 33 B', ha='center', fontdict=small_font)
ax.text(col[1]+box_w/2, row[1]+0.6, 'Range Proof: 675 B', ha='center', fontdict=small_font)
ax.text(col[1]+box_w/2, row[1]+0.2, '(Classical DLOG)', ha='center', fontdict={'family': 'sans-serif', 'size': 7, 'color': '#757575', 'style': 'italic'})

# [3] PAT Aggregation
draw_step(ax, col[2], 8.9, '3', colors['teal_border'])
draw_box(ax, col[2], row[0], box_w, box_h, colors['teal'], colors['teal_border'])
ax.text(col[2]+box_w/2, row[0]+1.9, 'PAT Aggregation', ha='center', fontdict=header_font)
ax.text(col[2]+box_w/2, row[0]+1.4, 'Merkle Commitment', ha='center', fontdict=body_font)
ax.text(col[2]+box_w/2, row[0]+1.0, '64-72 B root', ha='center', fontdict=small_font)
ax.text(col[2]+box_w/2, row[0]+0.5, '9,661× reduction', ha='center', fontdict=small_font)

# [4] LatticeFold+ Prover
draw_step(ax, col[3], 8.9, '4', colors['purple_border'])
draw_box(ax, col[3], row[0], box_w, box_h, colors['purple'], colors['purple_border'])
ax.text(col[3]+box_w/2, row[0]+1.9, 'LatticeFold+', ha='center', fontdict=header_font)
ax.text(col[3]+box_w/2, row[0]+1.4, '~1.38 KB proof', ha='center', fontdict=body_font)
ax.text(col[3]+box_w/2, row[0]+1.0, 'Binius64 Field', ha='center', fontdict=small_font)
ax.text(col[3]+box_w/2, row[0]+0.5, '~5 cycles/mul', ha='center', fontdict=small_font)

# ============ ROW 2: Block & Verification ============

# [5] Block Assembly
draw_step(ax, col[2], row[1]+2.4, '5', colors['gray_border'])
draw_box(ax, col[2], row[1], box_w, box_h, colors['gray'], colors['gray_border'])
ax.text(col[2]+box_w/2, row[1]+1.9, 'Block Assembly', ha='center', fontdict=header_font)
ax.text(col[2]+box_w/2, row[1]+1.4, 'Scrypt PoW', ha='center', fontdict=body_font)
ax.text(col[2]+box_w/2, row[1]+1.0, 'N=1024, r=1, p=1', ha='center', fontdict=small_font)
ax.text(col[2]+box_w/2, row[1]+0.5, 'Header + Proofs + TXs', ha='center', fontdict=small_font)

# [6] Node Verification
draw_step(ax, col[3], row[1]+2.4, '6', colors['blue_border'])
draw_box(ax, col[3], row[1], box_w, box_h, colors['blue'], colors['blue_border'])
ax.text(col[3]+box_w/2, row[1]+1.9, 'Node Verification', ha='center', fontdict=header_font)
ax.text(col[3]+box_w/2, row[1]+1.35, 'OP_CHECKFOLDPROOF', ha='center', fontdict=small_font)
ax.text(col[3]+box_w/2, row[1]+1.0, 'OP_CHECKPATAGG', ha='center', fontdict=small_font)
ax.text(col[3]+box_w/2, row[1]+0.65, 'BP++ Verify', ha='center', fontdict=small_font)
ax.text(col[3]+box_w/2, row[1]+0.3, 'Dilithium Verify', ha='center', fontdict=small_font)

# ============ ARROWS (all straight - horizontal or vertical) ============

# Row 1: Wallet -> Standard TX -> PAT -> LatticeFold+
draw_arrow_h(ax, col[0]+box_w, col[1], row[0]+box_h/2+0.5)  # Wallet to Standard TX (upper)
draw_arrow_h(ax, col[1]+box_w, col[2], row[0]+box_h/2)       # Standard TX to PAT
draw_arrow_h(ax, col[2]+box_w, col[3], row[0]+box_h/2)       # PAT to LatticeFold+

# Wallet -> Confidential TX (vertical then horizontal)
draw_arrow_v(ax, col[0]+box_w/2, row[0], row[1]+box_h)       # Wallet down
draw_arrow_h(ax, col[0]+box_w/2, col[1], row[1]+box_h/2)     # to Confidential TX

# LatticeFold+ -> Block Assembly (vertical)
draw_arrow_v(ax, col[3]+box_w/2, row[0], row[1]+box_h)       # LatticeFold+ down to Block level
draw_arrow_h(ax, col[3]+box_w/2, col[2]+box_w, row[1]+box_h/2)  # horizontal to Block

# Confidential TX -> Block Assembly (horizontal)
draw_arrow_h(ax, col[1]+box_w, col[2], row[1]+box_h/2)       # Confidential TX to Block

# Block Assembly -> Node Verification (horizontal)
draw_arrow_h(ax, col[2]+box_w, col[3], row[1]+box_h/2)       # Block to Verification

# ============ LEGEND ============
legend_y = 0.8
ax.text(0.8, legend_y+0.8, 'Security:', ha='left', fontdict=header_font)
legend_items = [
    (colors['green'], colors['green_border'], 'Dilithium: NIST Level 2 (128-bit quantum)'),
    (colors['amber'], colors['amber_border'], 'Bulletproofs++: 128-bit classical (DLOG)'),
    (colors['purple'], colors['purple_border'], 'LatticeFold+: Soundness < 2⁻¹³⁰'),
]
for i, (fill, border, text) in enumerate(legend_items):
    y = legend_y + 0.3 - i*0.35
    rect = FancyBboxPatch((0.8, y-0.08), 0.25, 0.18, boxstyle="round,rounding_size=0.03",
                           facecolor=fill, edgecolor=border, linewidth=1.5)
    ax.add_patch(rect)
    ax.text(1.2, y, text, ha='left', va='center', fontdict=small_font)

# ============ METRICS ============
ax.text(7.5, legend_y+0.8, 'Performance:', ha='left', fontdict=header_font)
metrics = [
    'Dilithium Verify: 0.04 ms',
    'PAT Verify: <4 µs', 
    'LatticeFold+ Verify: 0.68 ms',
    'BP++ Verify: 0.89 ms',
]
for i, m in enumerate(metrics):
    ax.text(7.5, legend_y+0.3-i*0.35, f'• {m}', ha='left', fontdict=small_font)

# Save
plt.tight_layout()
plt.savefig('paper_plots/architecture.png', dpi=300, bbox_inches='tight', facecolor='white')
plt.savefig('../images/architecture.png', dpi=300, bbox_inches='tight', facecolor='white')
print("Saved to paper_plots/architecture.png and ../images/architecture.png")
