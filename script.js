document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initScrollEffects();
    initCodeCopy();
});

function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href');
            const targetSection = document.querySelector(targetId);
            
            if (targetSection) {
                targetSection.scrollIntoView({ behavior: 'smooth' });
                updateActiveNav(link);
            }
        });
    });
    
    window.addEventListener('scroll', updateNavOnScroll);
}

function updateActiveNav(activeLink) {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.style.color = '';
    });
    activeLink.style.color = 'var(--primary-light)';
}

function updateNavOnScroll() {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-link');
    
    let current = '';
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (pageYOffset >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });
    
    navLinks.forEach(link => {
        link.style.color = '';
        if (link.getAttribute('href') === `#${current}`) {
            link.style.color = 'var(--primary-light)';
        }
    });
}

function initScrollEffects() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -100px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    const elements = document.querySelectorAll('.why-card, .feature-item, .component-card, .github-card, .setup-step, .doc-section');
    elements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease-out, transform 0.6s ease-out';
        observer.observe(el);
    });
}

function initCodeCopy() {
    const codeBlocks = document.querySelectorAll('.code-block');
    
    codeBlocks.forEach(block => {
        const code = block.querySelector('code');
        if (code) {
            const copyButton = document.createElement('button');
            copyButton.className = 'copy-button';
            copyButton.textContent = 'Copiar';
            copyButton.style.cssText = `
                position: absolute;
                top: 10px;
                right: 10px;
                padding: 0.5rem 1rem;
                background: var(--primary-light);
                color: white;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 0.9rem;
                font-weight: 600;
                transition: all 0.3s ease;
                opacity: 0;
            `;
            
            block.style.position = 'relative';
            block.appendChild(copyButton);
            
            block.addEventListener('mouseenter', () => {
                copyButton.style.opacity = '1';
            });
            
            block.addEventListener('mouseleave', () => {
                copyButton.style.opacity = '0';
            });
            
            copyButton.addEventListener('click', () => {
                const text = code.textContent;
                navigator.clipboard.writeText(text).then(() => {
                    const originalText = copyButton.textContent;
                    copyButton.textContent = 'Copiado!';
                    copyButton.style.background = 'var(--success-color)';
                    
                    setTimeout(() => {
                        copyButton.textContent = originalText;
                        copyButton.style.background = 'var(--primary-light)';
                    }, 2000);
                }).catch(err => {
                    console.error('Erro ao copiar:', err);
                });
            });
        }
    });
}

window.addEventListener('scroll', () => {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.boxShadow = '0 10px 30px rgba(59, 130, 246, 0.1)';
    } else {
        navbar.style.boxShadow = 'none';
    }
});
