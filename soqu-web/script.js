document.addEventListener('DOMContentLoaded', () => {
    // Intersection Observer for scroll animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Elements to animate
    const animatedElements = document.querySelectorAll('.card, .hero-text, .hero-visual, .tech-info, .tech-visual');

    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
        observer.observe(el);
    });

    // Add visible class styles dynamically
    const style = document.createElement('style');
    style.textContent = `
        .visible {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }
    `;
    document.head.appendChild(style);

    // Terminal typing effect (simple loop)
    const cursor = document.querySelector('.prompt');
    if (cursor) {
        setInterval(() => {
            cursor.style.opacity = cursor.style.opacity === '0' ? '1' : '0';
        }, 500);
    }

    // Mobile Menu Toggle
    const menuToggle = document.querySelector('.mobile-menu-toggle');
    const navLinks = document.querySelector('.nav-links');

    if (menuToggle) {
        menuToggle.addEventListener('click', () => {
            menuToggle.classList.toggle('active');
            navLinks.classList.toggle('active');
        });

        // Close menu when clicking a link
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                menuToggle.classList.remove('active');
                navLinks.classList.remove('active');
            });
        });

        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (!menuToggle.contains(e.target) && !navLinks.contains(e.target)) {
                menuToggle.classList.remove('active');
                navLinks.classList.remove('active');
            }
        });
    }

    // Block Explorer
    const blocksList = document.getElementById('blocks-list');
    const latestBlockEl = document.getElementById('latest-block');

    let currentBlock = 12405;
    const blocks = [];

    // Generate random hash
    function generateHash() {
        const chars = '0123456789abcdef';
        let hash = '0000';
        for (let i = 0; i < 60; i++) {
            hash += chars[Math.floor(Math.random() * chars.length)];
        }
        return hash;
    }

    // Format time ago
    function timeAgo(seconds) {
        if (seconds < 60) return `${seconds}s ago`;
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}m ago`;
        const hours = Math.floor(minutes / 60);
        return `${hours}h ago`;
    }

    // Create block card
    function createBlockCard(block) {
        const card = document.createElement('div');
        card.className = 'block-card';
        card.innerHTML = `
            <div class="block-header">
                <div class="block-height">Block #${block.height.toLocaleString()}</div>
                <div class="block-time">${timeAgo(block.timeAgo)}</div>
            </div>
            <div class="block-info">
                <div class="block-detail">
                    <div class="block-detail-label">Hash</div>
                    <div class="block-detail-value block-hash">${block.hash.substring(0, 16)}...${block.hash.substring(block.hash.length - 8)}</div>
                </div>
                <div class="block-detail">
                    <div class="block-detail-label">Transactions</div>
                    <div class="block-detail-value">${block.txs}</div>
                </div>
                <div class="block-detail">
                    <div class="block-detail-label">Miner</div>
                    <div class="block-detail-value">${block.miner}</div>
                </div>
                <div class="block-detail">
                    <div class="block-detail-label">Size</div>
                    <div class="block-detail-value">${block.size} KB</div>
                </div>
            </div>
        `;
        return card;
    }

    // Initialize blocks
    for (let i = 0; i < 10; i++) {
        blocks.push({
            height: currentBlock - i,
            hash: generateHash(),
            timeAgo: i * 30 + Math.floor(Math.random() * 30),
            txs: Math.floor(Math.random() * 50) + 1,
            miner: 'Pool #' + (Math.floor(Math.random() * 5) + 1),
            size: (Math.random() * 200 + 50).toFixed(1)
        });
    }

    // Render blocks
    blocks.forEach(block => {
        blocksList.appendChild(createBlockCard(block));
    });

    // Simulate new blocks
    setInterval(() => {
        currentBlock++;
        latestBlockEl.textContent = currentBlock.toLocaleString();

        // Update all block times
        blocks.forEach(block => block.timeAgo += 10);

        // Add new block at the top
        blocks.unshift({
            height: currentBlock,
            hash: generateHash(),
            timeAgo: 0,
            txs: Math.floor(Math.random() * 50) + 1,
            miner: 'Pool #' + (Math.floor(Math.random() * 5) + 1),
            size: (Math.random() * 200 + 50).toFixed(1)
        });

        // Keep only 10 blocks
        if (blocks.length > 10) {
            blocks.pop();
        }

        // Re-render all blocks with fade animation
        blocksList.style.opacity = '0';
        setTimeout(() => {
            blocksList.innerHTML = '';
            blocks.forEach(block => {
                blocksList.appendChild(createBlockCard(block));
            });
            blocksList.style.opacity = '1';
        }, 200);
    }, 10000); // New block every 10 seconds for demo

    // Add transition to blocks list
    blocksList.style.transition = 'opacity 0.3s ease';
});

// ========== sSOQ INTEGRATION CODE ==========

// Scam Alert Banner Management
function dismissScamAlert() {
    const banner = document.getElementById('scamAlertBanner');
    if (banner) {
        banner.classList.add('hidden');
        localStorage.setItem('scamAlertDismissed', 'true');
    }
}

// Check if user previously dismissed the alert
window.addEventListener('DOMContentLoaded', () => {
    const dismissed = localStorage.getItem('scamAlertDismissed');
    const banner = document.getElementById('scamAlertBanner');
    if (dismissed === 'true' && banner) {
        banner.classList.add('hidden');
    }
});

// Contract Address Copy Function
function copyContract() {
    const contractText = document.getElementById('ssoqContract')?.textContent;
    if (!contractText) return;

    if (contractText.includes('Deploying')) {
        alert('⚠️ Contract not yet deployed. Check back December 6, 2025.');
        return;
    }

    navigator.clipboard.writeText(contractText).then(() => {
        alert('✅ Contract address copied! Verify independently before interacting.');
    }).catch(() => {
        alert('⚠️ Copy failed. Please select and copy manually.');
    });
}

