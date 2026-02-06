# 🎨 Руководство по использованию анимаций

## 📦 Что было добавлено

### Новые файлы:

1. **`/static/css/animations-enhanced.css`** - Расширенные CSS анимации
2. **`/static/js/react-bits-vanilla.js`** - React-Bits компоненты для Vanilla JS
3. **`/static/js/gsap-animations.js`** - GSAP анимации контроллер
4. **`/static/js/particles-config.js`** - Конфигурация particles.js

### Обновленные файлы:

1. **`templates/base.html`** - Добавлены ссылки на новые файлы
2. **`templates/dashboard.html`** - Добавлены data-атрибуты для анимаций

---

## 🚀 Быстрый старт

Все анимации **автоматически инициализируются** при загрузке страницы. Просто добавьте соответствующие классы или data-атрибуты к вашим элементам.

---

## 📚 Использование компонентов

### 1. **Магнитные кнопки** (Magnetic Buttons)

Кнопки, следующие за курсором при hover.

```html
<button class="magnetic-btn" data-magnetic-btn>
    Нажми меня
</button>
```

**Или через JavaScript:**
```javascript
new ReactBits.MagneticButton('.my-button', {
    strength: 0.3,  // Сила притяжения (0-1)
    tolerance: 50   // Зона действия
});
```

---

### 2. **Spotlight Cards** 

Карточки со световым эффектом при hover.

```html
<div class="spotlight-card" data-spotlight>
    Контент карточки
</div>
```

**CSS для spotlight эффекта:**
```css
.spotlight-card::before {
    /* Эффект уже в animations-enhanced.css */
}
```

---

### 3. **Text Reveal**

Появление текста по буквам.

```html
<h1 class="text-reveal" data-text-reveal>
    Vulnerability Manager
</h1>
```

**Или через JavaScript:**
```javascript
new ReactBits.TextReveal('.my-heading', {
    delay: 50,              // ms между буквами
    animationDuration: 300, // длительность анимации
    splitBy: 'char'        // 'char' или 'word'
});
```

---

### 4. **Particle Buttons**

Кнопки с разлетающимися частицами при клике.

```html
<button class="particle-btn" data-particle-btn>
    Кликни меня
</button>
```

**Кастомизация:**
```javascript
new ReactBits.ParticleButton('.my-btn', {
    particleCount: 30,
    colors: ['#60a5fa', '#3b82f6', '#8b5cf6'],
    duration: 1000
});
```

---

### 5. **Ripple Effect**

Эффект ряби при клике.

```html
<div class="my-card" data-ripple>
    <div class="ripple-container"></div>
    Контент
</div>
```

---

### 6. **Tilt Cards**

3D наклон карточек при hover.

```html
<div class="card" data-tilt>
    Контент карточки
</div>
```

**Настройки:**
```javascript
new ReactBits.TiltCard('.card', {
    maxTilt: 10,        // Максимальный угол наклона
    perspective: 1000,  // Перспектива
    scale: 1.02        // Масштаб при hover
});
```

---

## 🎯 GSAP Анимации

### Счетчики (Counter Animation)

```html
<div class="counter" data-value="1234" data-duration="2">0</div>
```

Счетчик автоматически анимируется от 0 до значения `data-value`.

---

### Scroll Reveal

```html
<div class="scroll-reveal" 
     data-reveal-direction="up" 
     data-reveal-distance="50"
     data-reveal-delay="0.2">
    Появится при скролле
</div>
```

**Направления:**
- `up` - снизу вверх
- `down` - сверху вниз
- `left` - справа налево
- `right` - слева направо
- `scale` - масштабирование

---

### Parallax Эффект

```html
<div class="parallax-element">
    Фоновый элемент
</div>
```

```javascript
gsapAnimations.addParallax('.parallax-element', 0.5);
```

---

### Модальные окна

```javascript
// Показать
gsapAnimations.showModal('#myModal');

// Скрыть
gsapAnimations.hideModal('#myModal');
```

---

### Уведомления

```javascript
const notification = document.querySelector('.notification');
gsapAnimations.showNotification(notification);
```

---

## 🌟 AOS (Animate On Scroll)

Используйте data-атрибуты AOS для анимации при скролле:

```html
<div data-aos="fade-up" 
     data-aos-delay="100"
     data-aos-duration="600">
    Контент
</div>
```

**Популярные эффекты:**
- `fade-up` / `fade-down` / `fade-left` / `fade-right`
- `zoom-in` / `zoom-out`
- `flip-left` / `flip-right`
- `slide-up` / `slide-down`

**Настройки:**
- `data-aos-delay="200"` - задержка в ms
- `data-aos-duration="800"` - длительность в ms
- `data-aos-easing="ease-out-cubic"` - тип easing

---

## 🎨 Hover.css Эффекты

Просто добавьте классы:

```html
<!-- Float эффект -->
<button class="hvr-float">Кнопка</button>

<!-- Grow эффект -->
<div class="hvr-grow">Карточка</div>

<!-- Pulse эффект -->
<div class="hvr-pulse">Пульсация</div>

<!-- Icon Forward -->
<a class="hvr-icon-forward">
    <i class="fas fa-arrow-right hvr-icon"></i>
    Ссылка
</a>

<!-- Underline from center -->
<a class="hvr-underline-from-center">Ссылка</a>
```

---

## ✨ Animate.css Классы

```html
<!-- Bounce In -->
<div class="animate__animated animate__bounceIn">
    Появление с bounce
</div>

<!-- Fade In Up -->
<div class="animate__animated animate__fadeInUp">
    Появление снизу
</div>

<!-- RubberBand (для кнопок) -->
<button class="animate__animated animate__rubberBand">
    CTA кнопка
</button>

<!-- С задержкой -->
<div class="animate__animated animate__fadeIn animate__delay-2s">
    С задержкой 2 секунды
</div>
```

**Доступные задержки:**
- `animate__delay-1s`
- `animate__delay-2s`
- `animate__delay-3s`
- `animate__delay-4s`
- `animate__delay-5s`

---

## 🎪 Magic Animations

```html
<!-- Puff In (для hero) -->
<h1 class="magictime puffIn">Заголовок</h1>

<!-- Tin Up In (для статистики) -->
<div class="magictime tinUpIn">Карточка</div>

<!-- Swash In (для модалок) -->
<div class="magictime swashIn">Модальное окно</div>

<!-- Bomb Right Out (для удаления) -->
<div class="magictime bombRightOut">Удаляется</div>
```

---

## 🌊 Particles.js

### Автоматическая инициализация:

```html
<div id="particles-bg" data-particles="dashboard"></div>
```

**Доступные конфиги:**
- `dashboard` - умеренные частицы для фона
- `hero` - интенсивные для hero-секции
- `login` - минимальные для страницы входа
- `analytics` - научная тема

### Через JavaScript:

```javascript
// Инициализация
particlesManager.init('hero-particles', 'hero');

// Остановка
particlesManager.destroy('hero-particles');

// Пауза/возобновление
particlesManager.toggle('hero-particles', true);
```

---

## 🎯 Комбинированные эффекты

### Карточка со всеми эффектами:

```html
<div class="stat-card spotlight-card hvr-float" 
     data-aos="fade-up" 
     data-aos-delay="100"
     data-spotlight
     data-tilt
     data-ripple>
    <div class="stat-card-icon animate__animated animate__bounceIn">
        <i class="fas fa-bug counter-icon"></i>
    </div>
    <div class="stat-card-value counter" data-value="1234">0</div>
    <div class="stat-card-label">Уязвимостей</div>
    <div class="ripple-container"></div>
</div>
```

### CTA кнопка с максимальными эффектами:

```html
<button class="magnetic-btn cta-button particle-btn hvr-icon-forward animate__animated animate__rubberBand"
        data-magnetic-btn
        data-particle-btn
        data-ripple>
    <i class="fas fa-rocket hvr-icon"></i>
    Запустить парсинг
    <div class="ripple-container"></div>
</button>
```

---

## 📱 Мобильная оптимизация

Большинство эффектов автоматически отключаются на мобильных устройствах для производительности:

- Magnetic buttons
- Spotlight cards
- Tilt effects
- Particles (кроме login)

Проверка в коде:
```javascript
if (window.innerWidth < 768) {
    // Мобильная версия
}
```

---

## ♿ Accessibility

Все анимации поддерживают `prefers-reduced-motion`:

```css
@media (prefers-reduced-motion: reduce) {
    * {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
    }
}
```

Пользователи с включенной настройкой "Reduce Motion" не увидят анимаций.

---

## 🐛 Отладка

### Проверка инициализации:

Откройте консоль браузера, должны быть сообщения:
```
✨ React-Bits components initialized
✨ GSAP Animations initialized
✨ Particles Manager initialized
✨ Particles initialized for #particles-bg
```

### Refresh ScrollTrigger после динамических изменений:

```javascript
gsapAnimations.refresh();
```

### Полная остановка всех анимаций:

```javascript
gsapAnimations.killAll();
```

---

## 🎨 Кастомизация

### Изменение цветов particles:

```javascript
particlesManager.init('my-particles', 'dashboard', {
    particles: {
        color: { value: ['#ff0000', '#00ff00', '#0000ff'] }
    }
});
```

### Создание своей GSAP анимации:

```javascript
const tl = gsapAnimations.createTimeline({
    repeat: -1,
    yoyo: true
});

tl.to('.my-element', {
    x: 100,
    duration: 1,
    ease: 'power2.inOut'
});
```

---

## 📊 Performance Tips

1. **Используйте `will-change`** для анимируемых элементов:
```css
.animated-element {
    will-change: transform, opacity;
}
```

2. **Ленивая загрузка** particles на мобильных:
```javascript
if (window.innerWidth >= 768) {
    particlesManager.init('particles-bg', 'dashboard');
}
```

3. **Debounce** для scroll/resize событий (уже реализовано в GSAP).

4. **Используйте `once: true`** для AOS, если анимация нужна только один раз:
```html
<div data-aos="fade-up" data-aos-once="true">
```

---

## 🔗 Полезные ссылки

- [Animate.css Documentation](https://animate.style/)
- [AOS Documentation](https://michalsnik.github.io/aos/)
- [GSAP Documentation](https://greensock.com/docs/)
- [Particles.js Examples](https://vincentgarreau.com/particles.js/)
- [Hover.css Demo](https://ianlunn.github.io/Hover/)
- [Magic Animations Demo](https://www.minimamente.com/project/magic/)
- [React-Bits Repo](https://github.com/DavidHDev/react-bits)

---

## 🎉 Примеры использования

### Dashboard Hero Section:
```html
<section class="hero-section relative overflow-hidden py-12">
    <div id="hero-particles" data-particles="hero"></div>
    <h1 class="text-reveal magictime puffIn" data-text-reveal>
        Vulnerability Manager
    </h1>
    <button class="magnetic-btn cta-button particle-btn" 
            data-magnetic-btn 
            data-particle-btn>
        Запустить
    </button>
</section>
```

### Stat Cards Grid:
```html
<div class="grid grid-cols-4 gap-6">
    <div class="stat-card spotlight-card hvr-float" 
         data-aos="fade-up" 
         data-aos-delay="100"
         data-spotlight>
        <div class="counter" data-value="1234">0</div>
    </div>
</div>
```

### Table with animations:
```html
<div class="card-modern" data-aos="zoom-in">
    <table class="table-modern animated-grid">
        <tr data-ripple>
            <td class="hvr-underline-from-center">Строка 1</td>
        </tr>
    </table>
</div>
```

---

**Автор**: Claude Sonnet 4.5  
**Версия**: 1.0  
**Дата**: 2026-01-22

**Приятной работы с анимациями! ✨**

