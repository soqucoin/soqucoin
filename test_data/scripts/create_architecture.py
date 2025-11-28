from PIL import Image, ImageDraw, ImageFont

def create_architecture_diagram():
    # Canvas
    W, H = 1200, 800
    img = Image.new('RGB', (W, H), (255, 255, 255))
    draw = ImageDraw.Draw(img)
    
    try:
        font_title = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 28)
        font_label = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 18)
        font_small = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 14)
        font_badge = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 20)
    except:
        font_title = ImageFont.load_default()
        font_label = ImageFont.load_default()
        font_small = ImageFont.load_default()
        font_badge = ImageFont.load_default()

    # Colors
    C_BLUE = (220, 240, 255)
    C_GREEN = (220, 255, 220)
    C_RED = (255, 220, 220)
    C_GRAY = (245, 245, 245)
    C_BORDER = (80, 80, 80)
    C_LINE = (60, 60, 60)
    
    def draw_box(x, y, w, h, color, text, title=None):
        draw.rectangle([x, y, x+w, y+h], fill=color, outline=C_BORDER, width=2)
        if title:
            draw.text((x+15, y+10), title, font=font_label, fill=(0,0,0))
            # Draw separator line
            draw.line([x, y+35, x+w, y+35], fill=C_BORDER, width=1)
            # Draw content text centered in remaining space
            bbox = draw.textbbox((0,0), text, font=font_small)
            text_h = bbox[3] - bbox[1]
            draw.text((x+15, y+45), text, font=font_small, fill=(50,50,50))
        else:
            # Center text
            bbox = draw.textbbox((0,0), text, font=font_label)
            tx = x + (w - (bbox[2]-bbox[0]))//2
            ty = y + (h - (bbox[3]-bbox[1]))//2
            draw.text((tx, ty), text, font=font_label, fill=(0,0,0))

    def draw_badge(x, y, num):
        r = 15
        draw.ellipse([x-r, y-r, x+r, y+r], fill=(0,0,0))
        bbox = draw.textbbox((0,0), str(num), font=font_badge)
        tx = x - (bbox[2]-bbox[0])//2
        ty = y - (bbox[3]-bbox[1])//2
        draw.text((tx, ty), str(num), font=font_badge, fill=(255,255,255))

    def draw_connection(x1, y1, x2, y2):
        draw.line([x1, y1, x2, y2], fill=C_LINE, width=2)
        # Arrowhead
        import math
        angle = math.atan2(y2-y1, x2-x1)
        arrow_len = 10
        ax1 = x2 - arrow_len * math.cos(angle - math.pi/6)
        ay1 = y2 - arrow_len * math.sin(angle - math.pi/6)
        ax2 = x2 - arrow_len * math.cos(angle + math.pi/6)
        ay2 = y2 - arrow_len * math.sin(angle + math.pi/6)
        draw.polygon([x2, y2, ax1, ay1, ax2, ay2], fill=C_LINE)

    # Title
    draw.text((30, 30), "Soqucoin System Architecture", font=font_title, fill=(0,0,0))

    # 1. Transaction Layer
    draw_box(50, 150, 220, 300, C_GRAY, "", "Transaction Structure")
    draw_box(70, 200, 180, 50, C_BLUE, "Dilithium Signature\n(ML-DSA-44)")
    draw_box(70, 270, 180, 50, C_RED, "Confidential Amount\n(Pedersen Commitment)")
    draw_box(70, 340, 180, 50, (255,255,220), "UTXO Inputs\n(PrevOut Refs)")
    
    draw_badge(40, 140, 1)

    # 2. Aggregation Layer (PAT)
    draw_box(380, 150, 220, 120, C_GREEN, "PAT Aggregation\n(Merkle Tree)")
    draw_badge(370, 140, 2)
    
    # 3. Privacy Layer
    draw_box(380, 300, 220, 120, C_RED, "Bulletproofs++\nVerifier")
    draw_badge(370, 290, 2) # Also part of step 2 logic (verification)

    # 4. Folding Layer
    draw_box(700, 150, 220, 120, C_BLUE, "LatticeFold+\nProver\n(Recursive Folding)")
    draw_badge(690, 140, 3)

    # 5. Block Structure
    draw_box(1000, 150, 180, 400, C_GRAY, "", "Block Structure")
    draw_box(1020, 200, 140, 60, (230,230,230), "Header\n(Merkle Root)")
    draw_box(1020, 280, 140, 60, C_BLUE, "LatticeFold+\nProof (1.3KB)")
    draw_box(1020, 360, 140, 60, C_RED, "Bulletproofs++\nRange Proofs")
    draw_box(1020, 440, 140, 40, (230,230,230), "Coinbase")
    
    draw_badge(990, 140, 4)

    # Connections
    # Tx -> PAT
    draw_connection(270, 225, 380, 210)
    
    # Tx -> Privacy
    draw_connection(270, 295, 380, 360)
    
    # PAT -> Prover
    draw_connection(600, 210, 700, 210)
    
    # Prover -> Block (LF Proof)
    draw_connection(920, 210, 1020, 310)
    
    # Privacy -> Block (BP Proofs)
    draw_connection(600, 360, 1020, 390)
    
    # PAT Root -> Header
    draw_connection(600, 180, 1020, 230)

    # Legend Area
    ly = 600
    draw.text((50, ly), "Process Flow:", font=font_title, fill=(0,0,0))
    
    def draw_legend_item(y, num, text):
        draw_badge(70, y+10, num)
        draw.text((100, y), text, font=font_label, fill=(0,0,0))

    draw_legend_item(ly+50, 1, "Transaction Generation: User creates tx with Dilithium signatures and confidential commitments.")
    draw_legend_item(ly+90, 2, "Aggregation & Verification: Signatures batched via PAT; Confidential amounts verified via Bulletproofs++.")
    draw_legend_item(ly+130, 3, "Recursive Folding: PAT commitment folded into succinct LatticeFold+ proof by prover.")
    draw_legend_item(ly+170, 4, "Block Assembly: Block header commits to txs; includes LF+ proof and BP++ range proofs.")

    img.save("soqu-web/whitepaper/paper_plots/architecture.png")
    print("Architecture diagram created!")

if __name__ == "__main__":
    create_architecture_diagram()
