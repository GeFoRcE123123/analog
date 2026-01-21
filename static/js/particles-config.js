/**
 * Particles.js Configuration для Vulnerability Manager
 * Enhanced конфигурация с интерактивностью
 * 
 * Автор: Claude Sonnet 4.5
 * Дата: 2026-01-22
 */

// ================================================
// MAIN PARTICLES CONFIG
// ================================================
const particlesConfig = {
    // Dashboard background particles (умеренные)
    dashboard: {
        particles: {
            number: {
                value: 50,
                density: {
                    enable: true,
                    value_area: 800
                }
            },
            color: {
                value: ['#60a5fa', '#3b82f6', '#8b5cf6']
            },
            shape: {
                type: ['circle', 'triangle'],
                stroke: {
                    width: 0,
                    color: '#000000'
                }
            },
            opacity: {
                value: 0.4,
                random: true,
                anim: {
                    enable: true,
                    speed: 1,
                    opacity_min: 0.1,
                    sync: false
                }
            },
            size: {
                value: 4,
                random: true,
                anim: {
                    enable: true,
                    speed: 2,
                    size_min: 1,
                    sync: false
                }
            },
            line_linked: {
                enable: true,
                distance: 150,
                color: '#3b82f6',
                opacity: 0.3,
                width: 1
            },
            move: {
                enable: true,
                speed: 2,
                direction: 'none',
                random: true,
                straight: false,
                out_mode: 'out',
                bounce: false,
                attract: {
                    enable: false,
                    rotateX: 600,
                    rotateY: 1200
                }
            }
        },
        interactivity: {
            detect_on: 'canvas',
            events: {
                onhover: {
                    enable: true,
                    mode: 'grab'
                },
                onclick: {
                    enable: true,
                    mode: 'push'
                },
                resize: true
            },
            modes: {
                grab: {
                    distance: 140,
                    line_linked: {
                        opacity: 0.6
                    }
                },
                push: {
                    particles_nb: 4
                },
                remove: {
                    particles_nb: 2
                }
            }
        },
        retina_detect: true
    },

    // Hero section particles (интенсивные)
    hero: {
        particles: {
            number: {
                value: 80,
                density: {
                    enable: true,
                    value_area: 600
                }
            },
            color: {
                value: ['#60a5fa', '#3b82f6', '#8b5cf6', '#a78bfa']
            },
            shape: {
                type: ['circle', 'triangle', 'edge'],
                stroke: {
                    width: 0,
                    color: '#000000'
                }
            },
            opacity: {
                value: 0.5,
                random: true,
                anim: {
                    enable: true,
                    speed: 1.5,
                    opacity_min: 0.1,
                    sync: false
                }
            },
            size: {
                value: 5,
                random: true,
                anim: {
                    enable: true,
                    speed: 3,
                    size_min: 1,
                    sync: false
                }
            },
            line_linked: {
                enable: true,
                distance: 120,
                color: '#8b5cf6',
                opacity: 0.4,
                width: 1.5
            },
            move: {
                enable: true,
                speed: 3,
                direction: 'none',
                random: true,
                straight: false,
                out_mode: 'out',
                bounce: false,
                attract: {
                    enable: true,
                    rotateX: 600,
                    rotateY: 1200
                }
            }
        },
        interactivity: {
            detect_on: 'canvas',
            events: {
                onhover: {
                    enable: true,
                    mode: ['grab', 'bubble']
                },
                onclick: {
                    enable: true,
                    mode: 'push'
                },
                resize: true
            },
            modes: {
                grab: {
                    distance: 200,
                    line_linked: {
                        opacity: 0.8
                    }
                },
                bubble: {
                    distance: 200,
                    size: 8,
                    duration: 2,
                    opacity: 0.8,
                    speed: 3
                },
                push: {
                    particles_nb: 6
                },
                remove: {
                    particles_nb: 2
                }
            }
        },
        retina_detect: true
    },

    // Login page particles (минимальные)
    login: {
        particles: {
            number: {
                value: 30,
                density: {
                    enable: true,
                    value_area: 800
                }
            },
            color: {
                value: ['#3b82f6', '#8b5cf6']
            },
            shape: {
                type: 'circle'
            },
            opacity: {
                value: 0.3,
                random: true
            },
            size: {
                value: 3,
                random: true
            },
            line_linked: {
                enable: true,
                distance: 150,
                color: '#3b82f6',
                opacity: 0.2,
                width: 1
            },
            move: {
                enable: true,
                speed: 1.5,
                direction: 'none',
                random: true,
                straight: false,
                out_mode: 'out'
            }
        },
        interactivity: {
            detect_on: 'canvas',
            events: {
                onhover: {
                    enable: true,
                    mode: 'repulse'
                },
                onclick: {
                    enable: false
                },
                resize: true
            },
            modes: {
                repulse: {
                    distance: 100,
                    duration: 0.4
                }
            }
        },
        retina_detect: true
    },

    // Analytics page particles (scientific theme)
    analytics: {
        particles: {
            number: {
                value: 60,
                density: {
                    enable: true,
                    value_area: 800
                }
            },
            color: {
                value: ['#10b981', '#3b82f6', '#06b6d4']
            },
            shape: {
                type: ['circle', 'edge', 'triangle']
            },
            opacity: {
                value: 0.4,
                random: true
            },
            size: {
                value: 3,
                random: true
            },
            line_linked: {
                enable: true,
                distance: 130,
                color: '#10b981',
                opacity: 0.3,
                width: 1
            },
            move: {
                enable: true,
                speed: 2.5,
                direction: 'none',
                random: true,
                straight: false,
                out_mode: 'out'
            }
        },
        interactivity: {
            detect_on: 'canvas',
            events: {
                onhover: {
                    enable: true,
                    mode: 'grab'
                },
                onclick: {
                    enable: true,
                    mode: 'bubble'
                },
                resize: true
            },
            modes: {
                grab: {
                    distance: 150,
                    line_linked: {
                        opacity: 0.5
                    }
                },
                bubble: {
                    distance: 200,
                    size: 6,
                    duration: 2,
                    opacity: 0.6
                }
            }
        },
        retina_detect: true
    }
};

// ================================================
// PARTICLES MANAGER CLASS
// ================================================
class ParticlesManager {
    constructor() {
        this.instances = {};
    }

    /**
     * Инициализация particles для элемента
     * @param {string} elementId - ID элемента
     * @param {string} configName - Название конфига (dashboard, hero, login, analytics)
     * @param {object} customConfig - Кастомная конфигурация (опционально)
     */
    init(elementId, configName = 'dashboard', customConfig = null) {
        const element = document.getElementById(elementId);
        if (!element) {
            console.warn(`Element #${elementId} not found`);
            return;
        }

        // Skip на мобильных для производительности
        if (window.innerWidth < 768 && configName !== 'login') {
            console.log('Skipping particles on mobile for performance');
            return;
        }

        const config = customConfig || particlesConfig[configName] || particlesConfig.dashboard;

        if (window.particlesJS) {
            window.particlesJS(elementId, config);
            this.instances[elementId] = true;
            console.log(`✨ Particles initialized for #${elementId}`);
        } else {
            console.warn('Particles.js not loaded');
        }
    }

    /**
     * Остановка particles
     * @param {string} elementId
     */
    destroy(elementId) {
        const element = document.getElementById(elementId);
        if (element && window.pJSDom) {
            const instance = window.pJSDom.find(p => p.pJS.canvas.el.id === elementId);
            if (instance) {
                instance.pJS.fn.vendors.destroypJS();
                delete this.instances[elementId];
                console.log(`Particles destroyed for #${elementId}`);
            }
        }
    }

    /**
     * Пауза/возобновление particles
     * @param {string} elementId
     * @param {boolean} pause
     */
    toggle(elementId, pause = true) {
        if (window.pJSDom) {
            const instance = window.pJSDom.find(p => p.pJS.canvas.el.id === elementId);
            if (instance) {
                if (pause) {
                    instance.pJS.fn.vendors.stop();
                } else {
                    instance.pJS.fn.vendors.start();
                }
            }
        }
    }

    /**
     * Обновление параметров particles
     * @param {string} elementId
     * @param {object} updates
     */
    update(elementId, updates) {
        if (window.pJSDom) {
            const instance = window.pJSDom.find(p => p.pJS.canvas.el.id === elementId);
            if (instance) {
                Object.assign(instance.pJS.particles, updates);
            }
        }
    }

    /**
     * Auto-init всех элементов с data-particles
     */
    autoInit() {
        const elements = document.querySelectorAll('[data-particles]');
        elements.forEach(el => {
            const configName = el.getAttribute('data-particles') || 'dashboard';
            this.init(el.id, configName);
        });
    }
}

// ================================================
// GLOBAL INSTANCE
// ================================================
window.ParticlesManager = ParticlesManager;
window.particlesManager = new ParticlesManager();

// Auto-initialize
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Инициализируем particles для dashboard background (если есть)
        const dashboardBg = document.getElementById('particles-bg');
        if (dashboardBg) {
            window.particlesManager.init('particles-bg', 'dashboard');
        }

        // Инициализируем hero particles (если есть)
        const heroBg = document.getElementById('hero-particles');
        if (heroBg) {
            window.particlesManager.init('hero-particles', 'hero');
        }

        // Auto-init с data-attributes
        window.particlesManager.autoInit();

        console.log('✨ Particles Manager initialized');
    });
} else {
    // Если DOM уже загружен
    const dashboardBg = document.getElementById('particles-bg');
    if (dashboardBg) {
        window.particlesManager.init('particles-bg', 'dashboard');
    }

    const heroBg = document.getElementById('hero-particles');
    if (heroBg) {
        window.particlesManager.init('hero-particles', 'hero');
    }

    window.particlesManager.autoInit();
}

// Export для ES6 модулей
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { particlesConfig, ParticlesManager };
}

