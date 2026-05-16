document.addEventListener('DOMContentLoaded', () => {
    initNavbar();
    initProtocolTabs();
    initCodeCopy();
    initScrollAnimations();
});

// Navbar scroll effect and active link tracking
function initNavbar() {
    const navbar = document.querySelector('.navbar');
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('section[id]');

    window.addEventListener('scroll', () => {
        // Scroll effect
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }

        // Active link tracking
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.clientHeight;
            if (pageYOffset >= sectionTop - 150) {
                current = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${current}`) {
                link.classList.add('active');
            }
        });
    });
}

// Protocol section tab switching
function initProtocolTabs() {
    const tabs = document.querySelectorAll('.protocol-tab');
    const panes = document.querySelectorAll('.tab-pane');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.getAttribute('data-target');

            // Update tabs
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Update panes
            panes.forEach(pane => {
                pane.classList.remove('active');
                if (pane.getAttribute('id') === target) {
                    pane.classList.add('active');
                }
            });
        });
    });
}

// Enhanced code copy functionality
function initCodeCopy() {
    const codeBlocks = document.querySelectorAll('.code-block');

    codeBlocks.forEach(block => {
        const code = block.querySelector('code');
        if (!code) return;

        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.textContent = 'Copiar';
        block.appendChild(copyBtn);

        copyBtn.addEventListener('click', () => {
            const text = code.textContent;
            navigator.clipboard.writeText(text).then(() => {
                const originalText = copyBtn.textContent;
                copyBtn.textContent = 'Copiado!';
                copyBtn.style.background = 'var(--success)';
                copyBtn.style.color = 'white';
                
                setTimeout(() => {
                    copyBtn.textContent = originalText;
                    copyBtn.style.background = '';
                    copyBtn.style.color = '';
                }, 2000);
            }).catch(err => {
                console.error('Erro ao copiar:', err);
            });
        });
    });
}

// Scroll animations using Intersection Observer
function initScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target); // Only animate once
            }
        });
    }, observerOptions);

    const animateElements = document.querySelectorAll('.animate-up, .card, .feature-card, .setup-card, .protocol-container, .terminal-window');
    
    animateElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'opacity 0.8s cubic-bezier(0.4, 0, 0.2, 1), transform 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
        observer.observe(el);
    });

    // Add a helper class for visibility
    const style = document.createElement('style');
    style.textContent = `
        .visible {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }
    `;
    document.head.appendChild(style);
}
