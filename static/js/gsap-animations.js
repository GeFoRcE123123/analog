/**
 * GSAP Animations Controller для Vulnerability Manager
 * Использует GSAP 3 + ScrollTrigger
 * 
 * Функции:
 * - Hero Parallax эффекты
 * - Scroll-triggered анимации
 * - Counter animations
 * - Navbar behavior
 * - Timeline animations
 * - Stagger effects
 * 
 * Автор: Claude Sonnet 4.5
 * Дата: 2026-01-22
 */

class GSAPAnimations {
    constructor() {
        this.gsap = window.gsap;
        this.ScrollTrigger = window.ScrollTrigger;
        
        if (!this.gsap || !this.ScrollTrigger) {
            console.warn('GSAP or ScrollTrigger not loaded');
            return;
        }

        this.gsap.registerPlugin(this.ScrollTrigger);
        this.init();
    }

    init() {
        // Проверяем, не включен ли reduced motion
        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            console.log('Reduced motion detected, skipping animations');
            return;
        }

        this.initNavbarAnimation();
        this.initHeroParallax();
        this.initStatCards();
        this.initCounters();
        this.initTableRows();
        this.initScrollReveal();
        this.initSmoothScroll();
        this.initPageTransitions();

        console.log('✨ GSAP Animations initialized');
    }

    // ================================================
    // NAVBAR ANIMATIONS
    // ================================================
    initNavbarAnimation() {
        const navbar = document.querySelector('.nav-modern');
        if (!navbar) return;

        // Появление navbar при загрузке
        this.gsap.from(navbar, {
            y: -100,
            opacity: 0,
            duration: 0.6,
            ease: 'power2.out'
        });

        // Скрытие/показ navbar при скролле
        let lastScrollY = 0;
        const showNavbar = () => {
            this.gsap.to(navbar, {
                y: 0,
                duration: 0.3,
                ease: 'power2.out'
            });
            navbar.classList.remove('hidden');
            navbar.classList.add('scrolled');
        };

        const hideNavbar = () => {
            this.gsap.to(navbar, {
                y: -100,
                duration: 0.3,
                ease: 'power2.in'
            });
            navbar.classList.add('hidden');
        };

        window.addEventListener('scroll', () => {
            const currentScrollY = window.scrollY;

            if (currentScrollY < 100) {
                showNavbar();
                navbar.classList.remove('scrolled');
            } else if (currentScrollY > lastScrollY && currentScrollY > 200) {
                // Scrolling down
                hideNavbar();
            } else {
                // Scrolling up
                showNavbar();
            }

            lastScrollY = currentScrollY;
        });
    }

    // ================================================
    // HERO SECTION PARALLAX
    // ================================================
    initHeroParallax() {
        const heroSection = document.querySelector('.hero-section');
        const heroBg = document.querySelector('.hero-bg');
        
        if (!heroSection || !heroBg) return;

        // Parallax эффект для фона
        this.gsap.to(heroBg, {
            yPercent: 30,
            ease: 'none',
            scrollTrigger: {
                trigger: heroSection,
                start: 'top top',
                end: 'bottom top',
                scrub: true
            }
        });

        // Появление контента hero
        const heroContent = heroSection.querySelectorAll('h1, p, button');
        this.gsap.from(heroContent, {
            y: 50,
            opacity: 0,
            duration: 0.8,
            stagger: 0.2,
            ease: 'power3.out',
            delay: 0.3
        });
    }

    // ================================================
    // STAT CARDS ANIMATION
    // ================================================
    initStatCards() {
        const statCards = document.querySelectorAll('.stat-card');
        if (statCards.length === 0) return;

        // Анимация появления с stagger
        this.gsap.from(statCards, {
            y: 60,
            opacity: 0,
            duration: 0.8,
            stagger: 0.15,
            ease: 'power3.out',
            scrollTrigger: {
                trigger: statCards[0].parentElement,
                start: 'top 80%',
                once: true
            }
        });

        // Hover animations для каждой карточки
        statCards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                this.gsap.to(card, {
                    y: -8,
                    scale: 1.02,
                    duration: 0.3,
                    ease: 'power2.out'
                });

                const icon = card.querySelector('.stat-card-icon');
                if (icon) {
                    this.gsap.to(icon, {
                        scale: 1.1,
                        rotation: 5,
                        duration: 0.3,
                        ease: 'back.out(1.7)'
                    });
                }
            });

            card.addEventListener('mouseleave', () => {
                this.gsap.to(card, {
                    y: 0,
                    scale: 1,
                    duration: 0.3,
                    ease: 'power2.out'
                });

                const icon = card.querySelector('.stat-card-icon');
                if (icon) {
                    this.gsap.to(icon, {
                        scale: 1,
                        rotation: 0,
                        duration: 0.3,
                        ease: 'back.out(1.7)'
                    });
                }
            });
        });
    }

    // ================================================
    // COUNTER ANIMATIONS
    // ================================================
    initCounters() {
        const counters = document.querySelectorAll('.counter[data-value]');
        if (counters.length === 0) return;

        counters.forEach(counter => {
            const target = parseFloat(counter.getAttribute('data-value'));
            const duration = counter.getAttribute('data-duration') || 2;

            this.ScrollTrigger.create({
                trigger: counter,
                start: 'top 80%',
                once: true,
                onEnter: () => {
                    this.gsap.to(counter, {
                        innerText: target,
                        duration: duration,
                        snap: { innerText: 1 },
                        ease: 'power1.inOut',
                        onUpdate: function() {
                            counter.innerText = Math.ceil(this.targets()[0].innerText);
                        }
                    });
                }
            });
        });
    }

    // ================================================
    // TABLE ROWS ANIMATION
    // ================================================
    initTableRows() {
        const tables = document.querySelectorAll('.table-modern tbody');
        if (tables.length === 0) return;

        tables.forEach(tbody => {
            const rows = tbody.querySelectorAll('tr');
            
            this.gsap.from(rows, {
                x: -30,
                opacity: 0,
                duration: 0.5,
                stagger: 0.05,
                ease: 'power2.out',
                scrollTrigger: {
                    trigger: tbody,
                    start: 'top 85%',
                    once: true
                }
            });
        });
    }

    // ================================================
    // SCROLL REVEAL (Generic)
    // ================================================
    initScrollReveal() {
        // Для элементов с классом .scroll-reveal
        const revealElements = document.querySelectorAll('.scroll-reveal');
        
        revealElements.forEach(element => {
            const direction = element.getAttribute('data-reveal-direction') || 'up';
            const distance = parseInt(element.getAttribute('data-reveal-distance')) || 50;
            const delay = parseFloat(element.getAttribute('data-reveal-delay')) || 0;

            let animateFrom = { opacity: 0 };
            
            switch (direction) {
                case 'up':
                    animateFrom.y = distance;
                    break;
                case 'down':
                    animateFrom.y = -distance;
                    break;
                case 'left':
                    animateFrom.x = -distance;
                    break;
                case 'right':
                    animateFrom.x = distance;
                    break;
                case 'scale':
                    animateFrom.scale = 0.8;
                    break;
            }

            this.gsap.from(element, {
                ...animateFrom,
                duration: 0.8,
                delay: delay,
                ease: 'power3.out',
                scrollTrigger: {
                    trigger: element,
                    start: 'top 85%',
                    once: true
                }
            });
        });
    }

    // ================================================
    // SMOOTH SCROLLING
    // ================================================
    initSmoothScroll() {
        // Smooth scroll для якорных ссылок
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', (e) => {
                const href = anchor.getAttribute('href');
                if (href === '#') return;

                const target = document.querySelector(href);
                if (target) {
                    e.preventDefault();
                    
                    this.gsap.to(window, {
                        duration: 1,
                        scrollTo: {
                            y: target,
                            offsetY: 80
                        },
                        ease: 'power3.inOut'
                    });
                }
            });
        });
    }

    // ================================================
    // PAGE TRANSITIONS
    // ================================================
    initPageTransitions() {
        // Fade in контента страницы
        const mainContent = document.querySelector('main');
        if (mainContent) {
            this.gsap.from(mainContent, {
                opacity: 0,
                duration: 0.5,
                ease: 'power2.out'
            });
        }
    }

    // ================================================
    // CARDS HOVER EFFECTS
    // ================================================
    addCardHoverEffect(cardSelector) {
        const cards = document.querySelectorAll(cardSelector);
        
        cards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                this.gsap.to(card, {
                    y: -10,
                    scale: 1.02,
                    boxShadow: '0 20px 40px rgba(0,0,0,0.15)',
                    duration: 0.3,
                    ease: 'power2.out'
                });
            });

            card.addEventListener('mouseleave', () => {
                this.gsap.to(card, {
                    y: 0,
                    scale: 1,
                    boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
                    duration: 0.3,
                    ease: 'power2.out'
                });
            });
        });
    }

    // ================================================
    // CUSTOM TIMELINE CREATION
    // ================================================
    createTimeline(options = {}) {
        return this.gsap.timeline(options);
    }

    // ================================================
    // PARSING PROGRESS ANIMATION
    // ================================================
    animateProgressBar(selector, targetPercent, duration = 1) {
        const progressBar = document.querySelector(selector);
        if (!progressBar) return;

        this.gsap.to(progressBar, {
            width: `${targetPercent}%`,
            duration: duration,
            ease: 'power2.out'
        });
    }

    // ================================================
    // MODAL ANIMATIONS
    // ================================================
    showModal(modalSelector) {
        const modal = document.querySelector(modalSelector);
        if (!modal) return;

        const overlay = modal;
        const content = modal.querySelector('.modal-content, [class*="modal"]');

        const tl = this.gsap.timeline();

        tl.set(modal, { display: 'flex' })
          .from(overlay, {
              opacity: 0,
              duration: 0.3,
              ease: 'power2.out'
          })
          .from(content, {
              opacity: 0,
              scale: 0.8,
              y: -50,
              duration: 0.4,
              ease: 'back.out(1.7)'
          }, '-=0.2');

        return tl;
    }

    hideModal(modalSelector) {
        const modal = document.querySelector(modalSelector);
        if (!modal) return;

        const overlay = modal;
        const content = modal.querySelector('.modal-content, [class*="modal"]');

        const tl = this.gsap.timeline({
            onComplete: () => {
                modal.style.display = 'none';
            }
        });

        tl.to(content, {
              opacity: 0,
              scale: 0.8,
              y: -50,
              duration: 0.3,
              ease: 'power2.in'
          })
          .to(overlay, {
              opacity: 0,
              duration: 0.2,
              ease: 'power2.in'
          }, '-=0.1');

        return tl;
    }

    // ================================================
    // NOTIFICATION ANIMATION
    // ================================================
    showNotification(element) {
        if (!element) return;

        const tl = this.gsap.timeline();
        
        tl.set(element, { display: 'block' })
          .from(element, {
              x: 100,
              opacity: 0,
              duration: 0.4,
              ease: 'back.out(1.7)'
          })
          .to(element, {
              x: 0,
              opacity: 1
          });

        // Auto hide after 5 seconds
        tl.to(element, {
            x: 100,
            opacity: 0,
            duration: 0.3,
            ease: 'power2.in',
            delay: 5
        }).set(element, { display: 'none' });

        return tl;
    }

    // ================================================
    // STAGGER ANIMATION HELPER
    // ================================================
    staggerAnimation(selector, animationProps, staggerAmount = 0.1) {
        const elements = document.querySelectorAll(selector);
        if (elements.length === 0) return;

        this.gsap.from(elements, {
            ...animationProps,
            stagger: staggerAmount,
            ease: animationProps.ease || 'power2.out'
        });
    }

    // ================================================
    // PARALLAX EFFECT HELPER
    // ================================================
    addParallax(selector, speed = 0.5) {
        const elements = document.querySelectorAll(selector);
        
        elements.forEach(element => {
            this.gsap.to(element, {
                yPercent: speed * 100,
                ease: 'none',
                scrollTrigger: {
                    trigger: element,
                    start: 'top bottom',
                    end: 'bottom top',
                    scrub: true
                }
            });
        });
    }

    // ================================================
    // REFRESH SCROLLTRIGGER
    // ================================================
    refresh() {
        if (this.ScrollTrigger) {
            this.ScrollTrigger.refresh();
        }
    }

    // ================================================
    // KILL ALL ANIMATIONS
    // ================================================
    killAll() {
        if (this.gsap) {
            this.gsap.killTweensOf('*');
        }
        if (this.ScrollTrigger) {
            this.ScrollTrigger.getAll().forEach(st => st.kill());
        }
    }
}

// ================================================
// GLOBAL INSTANCE
// ================================================
window.GSAPAnimations = GSAPAnimations;

// Auto-initialize
let gsapAnimations;

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        gsapAnimations = new GSAPAnimations();
        window.gsapAnimations = gsapAnimations;
    });
} else {
    gsapAnimations = new GSAPAnimations();
    window.gsapAnimations = gsapAnimations;
}

// Export for ES6 modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GSAPAnimations;
}

