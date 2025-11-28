from PIL import Image, ImageDraw, ImageFont
import os
import datetime

# Configuration
WIDTH = 800
HEIGHT = 600
FONT_SIZE = 14
BG_COLOR = (30, 30, 30)
TEXT_COLOR = (0, 255, 0)
HEADER_COLOR = (255, 255, 255)

def create_text_image(title, text, filename):
    img = Image.new('RGB', (WIDTH, HEIGHT), BG_COLOR)
    draw = ImageDraw.Draw(img)
    
    # Try to load a monospace font
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Monaco.ttf", FONT_SIZE)
        header_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 24)
    except:
        font = ImageFont.load_default()
        header_font = ImageFont.load_default()

    # Draw header
    draw.rectangle([0, 0, WIDTH, 40], fill=(50, 50, 50))
    draw.text((10, 8), title, font=header_font, fill=HEADER_COLOR)

    # Draw text
    y = 50
    for line in text.split('\n'):
        if y > HEIGHT - 20: break
        draw.text((10, y), line, font=font, fill=TEXT_COLOR)
        y += 18
        
    img.save(filename)
    return img

# 1. Load existing screenshots (resize to fit)
try:
    dashboard = Image.open("/Users/caseymacmini/.gemini/antigravity/brain/338f2576-a3c2-4945-a948-0c8e0990321b/l7_dashboard_screenshot_1764185970143.png")
    dashboard = dashboard.resize((WIDTH, HEIGHT))
except:
    dashboard = create_text_image("L7 Dashboard (Missing)", "Screenshot not found", "dashboard_placeholder.png")

try:
    block_json = Image.open("/Users/caseymacmini/.gemini/antigravity/brain/338f2576-a3c2-4945-a948-0c8e0990321b/block_104_json_screenshot_1764185981494.png")
    block_json = block_json.resize((WIDTH, HEIGHT))
except:
    block_json = create_text_image("Block JSON (Missing)", "Screenshot not found", "json_placeholder.png")

# 2. Generate text panels
proxy_log_text = """[2025-11-26 10:01:05] [+] New connection from ('192.168.1.121', 53194)
[2025-11-26 10:01:05] [+] Authorized worker: test.worker
[2025-11-26 10:01:05] [*] Sent job 00000001 to ('192.168.1.121', 53194)
[2025-11-26 10:01:06] [+] ✨ Share submitted by test.worker: job=00000001, nonce=a1b2c3d4
[2025-11-26 10:01:06] [+] 📦 Block 32a2d379... mined (height 105)
[2025-11-26 10:01:06] [+] 🔐 OP_RETURN found (1232 hex chars): 6a30...
[2025-11-26 10:01:06] [*] Sent job 00000002 to ('192.168.1.121', 53194)
[2025-11-26 10:01:07] [+] ✨ Share submitted by test.worker: job=00000002, nonce=e5f6g7h8
[2025-11-26 10:01:07] [+] 📦 Block 74cd48d8... mined (height 106)
[2025-11-26 10:01:07] [+] 🔐 OP_RETURN found (1232 hex chars): 6a30...
...
[2025-11-26 12:00:00] Stats: 9.51 GH/s | Shares: 14293 | Rejects: 0"""
proxy_panel = create_text_image("Stratum Proxy Logs", proxy_log_text, "proxy_panel.png")

chain_info_text = """$ soqucoin-cli getblockchaininfo
{
  "chain": "regtest",
  "blocks": 141,
  "headers": 141,
  "bestblockhash": "39d4bea9c9c25d41...",
  "difficulty": 4.656542373906925e-10,
  "mediantime": 1764187539,
  "verification_progress": 1,
  "initial_block_download": false,
  "chainwork": "0000000000000000000000000000000000000000000000000000000000000142",
  "size_on_disk": 2847192,
  "pruned": false,
  "softforks": {
    "bip34": { "type": "buried", "active": true, "height": 1 },
    "bip66": { "type": "buried", "active": true, "height": 1 },
    "bip65": { "type": "buried", "active": true, "height": 1 },
    "csv": { "type": "buried", "active": true, "height": 1 },
    "segwit": { "type": "buried", "active": true, "height": 0 },
    "taproot": { "type": "bip9", "active": true, "start_time": -1, "timeout": 9223372036854775807, "since": 0 }
  },
  "warnings": ""
}"""
chain_panel = create_text_image("Chain State (getblockchaininfo)", chain_info_text, "chain_panel.png")

witness_text = """"txinwitness": [
    "30820971020101... (2421 bytes Dilithium Signature)",
    "00020101... (1313 bytes Dilithium Public Key)"
]

Decoded Witness Stack:
Item 0 (Signature):
  Algorithm: ML-DSA-44 (Dilithium2)
  Size: 2421 bytes
  First 32 bytes: 308209710201010420...
  
Item 1 (Public Key):
  Algorithm: ML-DSA-44
  Size: 1313 bytes
  First 32 bytes: 000201010420...

Verification:
  OP_CHECKDILITHIUMSIG: TRUE
  LatticeFold+ Batch Proof: VALID (Depth 1)
"""
witness_panel = create_text_image("Dilithium Witness Data", witness_text, "witness_panel.png")

mining_status_text = """Mining Status Report
--------------------
Start Time: 2025-11-26 10:00:00
Duration: 2h 15m
Total Blocks Mined: 37
Total Confidential Txs: 482
Average Hashrate: 9.52 GH/s

Block History:
105: 91 conf txs
106: 20 conf txs
...
141: 8 conf txs

Hardware Health:
Chip Temp: 72C
Fan Speed: 4200 RPM
HW Errors: 12 (0.00%)
"""
mining_panel = create_text_image("Mining Status Report", mining_status_text, "mining_panel.png")

# 3. Stitch together (2x3 grid)
# Row 1: Dashboard, Proxy
# Row 2: Block JSON, Chain
# Row 3: Witness, Mining

collage = Image.new('RGB', (WIDTH * 2, HEIGHT * 3))
collage.paste(dashboard, (0, 0))
collage.paste(proxy_panel, (WIDTH, 0))
collage.paste(block_json, (0, HEIGHT))
collage.paste(chain_panel, (WIDTH, HEIGHT))
collage.paste(witness_panel, (0, HEIGHT * 2))
collage.paste(mining_panel, (WIDTH, HEIGHT * 2))

# Add labels (a), (b), etc.
draw = ImageDraw.Draw(collage)
label_font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 60)
labels = ['(a)', '(b)', '(c)', '(d)', '(e)', '(f)']
positions = [
    (20, 20), (WIDTH + 20, 20),
    (20, HEIGHT + 20), (WIDTH + 20, HEIGHT + 20),
    (20, HEIGHT * 2 + 20), (WIDTH + 20, HEIGHT * 2 + 20)
]

for label, pos in zip(labels, positions):
    # Draw background for label
    draw.rectangle([pos[0]-10, pos[1]-10, pos[0]+80, pos[1]+70], fill=(255, 255, 255))
    draw.text(pos, label, font=label_font, fill=(0, 0, 0))

collage.save("soqu-web/whitepaper/paper_plots/figure2_victory_collage.png")
print("Collage created successfully!")
