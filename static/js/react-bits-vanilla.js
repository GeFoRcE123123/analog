/**
 * React-Bits Inspired Components для Vanilla JS
 * Адаптация компонентов из https://github.com/DavidHDev/react-bits
 * Для использования в Flask приложении
 * 
 * Компоненты:
 * - MagneticButton: кнопки, следующие за курсором
 * - SpotlightCard: карточки со световым эффектом
 * - TextReveal: появление текста по буквам
 * - ParticleButton: кнопки с разлетающимися частицами
 * - RippleEffect: эффект ряби на кликах
 * - AnimatedGrid: сетка с wave-эффектом
 * 
 * Автор: Claude Sonnet 4.5
 * Дата: 2026-01-22
 */

// ================================================
// MAGNETIC BUTTON COMPONENT
// ================================================
class MagneticButton {
    constructor(selector, options = {}) {
        this.buttons = document.querySelectorAll(selector);
        this.options = {
            strength: options.strength || 0.3,
            tolerance: options.tolerance || 50,
            ...options
        };
        this.init();
    }

    init() {
        this.buttons.forEach(button => {
            // Skip on touch devices
            if ('ontouchstart' in window) {
                return;
            }

            const rect = button.getBoundingClientRect();
            let isHovering = false;

            button.addEventListener('mouseenter', () => {
                isHovering = true;
            });

            button.addEventListener('mousemove', (e) => {
                if (!isHovering) return;

                const rect = button.getBoundingClientRect();
                const centerX = rect.left + rect.width / 2;
                const centerY = rect.top + rect.height / 2;

                const deltaX = (e.clientX - centerX) * this.options.strength;
                const deltaY = (e.clientY - centerY) * this.options.strength;

                button.style.transform = `translate(${deltaX}px, ${deltaY}px)`;
            });

            button.addEventListener('mouseleave', () => {
                isHovering = false;
                button.style.transform = 'translate(0, 0)';
            });
        });
    }
}

// ================================================
// SPOTLIGHT CARD COMPONENT
// ================================================
class SpotlightCard {
    constructor(selector, options = {}) {
        this.cards = document.querySelectorAll(selector);
        this.options = {
            size: options.size || 200,
            intensity: options.intensity || 0.4,
            ...options
        };
        this.init();
    }

    init() {
        this.cards.forEach(card => {
            // Skip on mobile
            if (window.innerWidth < 768) {
                return;
            }

            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                card.style.setProperty('--mouse-x', `${x}px`);
                card.style.setProperty('--mouse-y', `${y}px`);
            });

            card.addEventListener('mouseleave', () => {
                card.style.setProperty('--mouse-x', '50%');
                card.style.setProperty('--mouse-y', '50%');
            });
        });
    }
}

// ================================================
// TEXT REVEAL ANIMATION COMPONENT
// ================================================
class TextReveal {
    constructor(selector, options = {}) {
        this.elements = document.querySelectorAll(selector);
        this.options = {
            delay: options.delay || 50, // ms between chars
            animationDuration: options.animationDuration || 300,
            splitBy: options.splitBy || 'char', // 'char' or 'word'
            ...options
        };
        this.init();
    }

    init() {
        this.elements.forEach((el, index) => {
            const text = el.textContent;
            el.textContent = '';
            el.style.opacity = '1';

            const items = this.options.splitBy === 'word' 
                ? text.split(' ').map(word => word + ' ')
                : text.split('');

            items.forEach((item, i) => {
                const span = document.createElement('span');
                span.textContent = item;
                span.style.display = 'inline-block';
                span.style.opacity = '0';
                span.style.transform = 'translateY(20px)';
                span.style.animation = `charReveal ${this.options.animationDuration}ms ease forwards`;
                span.style.animationDelay = `${(index * 100) + (i * this.options.delay)}ms`;
                span.className = 'char-reveal';
                el.appendChild(span);
            });
        });
    }
}

// ================================================
// PARTICLE BUTTON COMPONENT
// ================================================
class ParticleButton {
    constructor(selector, options = {}) {
        this.buttons = document.querySelectorAll(selector);
        this.options = {
            particleCount: options.particleCount || 30,
            colors: options.colors || ['#60a5fa', '#3b82f6', '#8b5cf6'],
            duration: options.duration || 1000,
            ...options
        };
        this.init();
    }

    init() {
        this.buttons.forEach(button => {
            button.addEventListener('click', (e) => {
                this.createParticles(e, button);
            });
        });
    }

    createParticles(e, button) {
        const rect = button.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;

        for (let i = 0; i < this.options.particleCount; i++) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            
            const angle = (Math.PI * 2 * i) / this.options.particleCount;
            const velocity = 50 + Math.random() * 50;
            const tx = Math.cos(angle) * velocity;
            const ty = Math.sin(angle) * velocity;

            particle.style.setProperty('--x', `${tx}px`);
            particle.style.setProperty('--y', `${ty}px`);
            particle.style.left = `${x}px`;
            particle.style.top = `${y}px`;
            particle.style.background = this.options.colors[Math.floor(Math.random() * this.options.colors.length)];

            button.appendChild(particle);

            setTimeout(() => {
                particle.remove();
            }, this.options.duration);
        }
    }
}

// ================================================
// RIPPLE EFFECT COMPONENT
// ================================================
class RippleEffect {
    constructor(selector, options = {}) {
        this.elements = document.querySelectorAll(selector);
        this.options = {
            color: options.color || 'rgba(255, 255, 255, 0.6)',
            duration: options.duration || 600,
            ...options
        };
        this.init();
    }

    init() {
        this.elements.forEach(element => {
            // Create ripple container if not exists
            if (!element.querySelector('.ripple-container')) {
                const container = document.createElement('div');
                container.className = 'ripple-container';
                element.style.position = 'relative';
                element.style.overflow = 'hidden';
                element.appendChild(container);
            }

            element.addEventListener('click', (e) => {
                this.createRipple(e, element);
            });
        });
    }

    createRipple(e, element) {
        const container = element.querySelector('.ripple-container');
        const ripple = document.createElement('span');
        ripple.className = 'ripple';

        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;

        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${x}px`;
        ripple.style.top = `${y}px`;
        ripple.style.background = this.options.color;

        container.appendChild(ripple);

        setTimeout(() => {
            ripple.remove();
        }, this.options.duration);
    }
}

// ================================================
// ANIMATED GRID COMPONENT
// ================================================
class AnimatedGrid {
    constructor(selector, options = {}) {
        this.grid = document.querySelector(selector);
        this.options = {
            itemSelector: options.itemSelector || '> *',
            animationDelay: options.animationDelay || 50,
            animationDuration: options.animationDuration || 600,
            ...options
        };
        this.init();
    }

    init() {
        if (!this.grid) return;

        const items = this.grid.querySelectorAll(this.options.itemSelector);
        
        // Use Intersection Observer для анимации при появлении
        const observer = new IntersectionObserver((entries) => {
            entries.forEach((entry, index) => {
                if (entry.isIntersecting) {
                    entry.target.style.animation = `gridWave ${this.options.animationDuration}ms ease-out ${index * this.options.animationDelay}ms backwards`;
                    observer.unobserve(entry.target);
                }
            });
        }, {
            threshold: 0.1
        });

        items.forEach(item => {
            observer.observe(item);
        });
    }
}

// ================================================
// MAGNETIC CURSOR (GLOBAL)
// ================================================
class MagneticCursor {
    constructor(options = {}) {
        this.options = {
            size: options.size || 10,
            color: options.color || '#3b82f6',
            magneticElements: options.magneticElements || '.magnetic',
            ...options
        };
        this.cursor = null;
        this.cursorTrail = [];
        this.init();
    }

    init() {
        // Skip on mobile
        if ('ontouchstart' in window) return;

        this.createCursor();
        this.bindEvents();
    }

    createCursor() {
        this.cursor = document.createElement('div');
        this.cursor.className = 'magnetic-cursor';
        this.cursor.style.cssText = `
            position: fixed;
            width: ${this.options.size}px;
            height: ${this.options.size}px;
            background: ${this.options.color};
            border-radius: 50%;
            pointer-events: none;
            z-index: 9999;
            mix-blend-mode: difference;
            transition: transform 0.2s ease;
        `;
        document.body.appendChild(this.cursor);
    }

    bindEvents() {
        let mouseX = 0;
        let mouseY = 0;
        let cursorX = 0;
        let cursorY = 0;

        document.addEventListener('mousemove', (e) => {
            mouseX = e.clientX;
            mouseY = e.clientY;
        });

        // Smooth cursor follow
        const animate = () => {
            const dx = mouseX - cursorX;
            const dy = mouseY - cursorY;

            cursorX += dx * 0.1;
            cursorY += dy * 0.1;

            if (this.cursor) {
                this.cursor.style.left = `${cursorX}px`;
                this.cursor.style.top = `${cursorY}px`;
            }

            requestAnimationFrame(animate);
        };

        animate();

        // Magnetic effect on hover
        const magneticElements = document.querySelectorAll(this.options.magneticElements);
        magneticElements.forEach(el => {
            el.addEventListener('mouseenter', () => {
                if (this.cursor) {
                    this.cursor.style.transform = 'scale(2)';
                }
            });

            el.addEventListener('mouseleave', () => {
                if (this.cursor) {
                    this.cursor.style.transform = 'scale(1)';
                }
            });
        });
    }
}

// ================================================
// SCROLL PROGRESS INDICATOR
// ================================================
class ScrollProgress {
    constructor(options = {}) {
        this.options = {
            color: options.color || '#3b82f6',
            height: options.height || 3,
            position: options.position || 'top',
            ...options
        };
        this.init();
    }

    init() {
        const progress = document.createElement('div');
        progress.className = 'scroll-progress';
        progress.style.cssText = `
            position: fixed;
            ${this.options.position}: 0;
            left: 0;
            width: 0%;
            height: ${this.options.height}px;
            background: ${this.options.color};
            z-index: 9999;
            transition: width 0.1s ease;
        `;
        document.body.appendChild(progress);

        window.addEventListener('scroll', () => {
            const windowHeight = document.documentElement.scrollHeight - window.innerHeight;
            const scrolled = (window.scrollY / windowHeight) * 100;
            progress.style.width = `${Math.min(scrolled, 100)}px`;
        });
    }
}

// ================================================
// TILT CARD EFFECT
// ================================================
class TiltCard {
    constructor(selector, options = {}) {
        this.cards = document.querySelectorAll(selector);
        this.options = {
            maxTilt: options.maxTilt || 10,
            perspective: options.perspective || 1000,
            scale: options.scale || 1.02,
            ...options
        };
        this.init();
    }

    init() {
        this.cards.forEach(card => {
            // Skip on mobile
            if (window.innerWidth < 768) return;

            card.style.transformStyle = 'preserve-3d';
            card.style.transition = 'transform 0.3s ease';

            card.addEventListener('mousemove', (e) => {
                const rect = card.getBoundingClientRect();
                const x = e.clientX - rect.left;
                const y = e.clientY - rect.top;

                const centerX = rect.width / 2;
                const centerY = rect.height / 2;

                const rotateX = ((y - centerY) / centerY) * this.options.maxTilt;
                const rotateY = ((centerX - x) / centerX) * this.options.maxTilt;

                card.style.transform = `perspective(${this.options.perspective}px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale(${this.options.scale})`;
            });

            card.addEventListener('mouseleave', () => {
                card.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) scale(1)';
            });
        });
    }
}

// ================================================
// AUTO-INITIALIZATION
// ================================================
window.ReactBits = {
    MagneticButton,
    SpotlightCard,
    TextReveal,
    ParticleButton,
    RippleEffect,
    AnimatedGrid,
    MagneticCursor,
    ScrollProgress,
    TiltCard,

    // Auto-init method
    initAll() {
        // Init all components with data attributes
        if (document.querySelectorAll('[data-magnetic-btn]').length > 0) {
            new MagneticButton('[data-magnetic-btn]');
        }

        if (document.querySelectorAll('[data-spotlight]').length > 0) {
            new SpotlightCard('[data-spotlight]');
        }

        if (document.querySelectorAll('[data-text-reveal]').length > 0) {
            new TextReveal('[data-text-reveal]');
        }

        if (document.querySelectorAll('[data-particle-btn]').length > 0) {
            new ParticleButton('[data-particle-btn]');
        }

        if (document.querySelectorAll('[data-ripple]').length > 0) {
            new RippleEffect('[data-ripple]');
        }

        if (document.querySelector('[data-animated-grid]')) {
            new AnimatedGrid('[data-animated-grid]');
        }

        if (document.querySelector('[data-tilt]')) {
            new TiltCard('[data-tilt]');
        }

        console.log('✨ React-Bits components initialized');
    }
};

// Auto-initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.ReactBits.initAll();
    });
} else {
    window.ReactBits.initAll();
}

// Export for ES6 modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.ReactBits;
}

