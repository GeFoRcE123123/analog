/**
 * 3D Force-Directed Graph Visualization
 * Three.js + D3.js force simulation в 3D
 */

// Глобальные переменные
let scene, camera, renderer, controls;
let nodes = [], links = [];
let nodeMeshes = [], linkLines = [];
let raycaster, mouse;
let selectedNode = null;
let hoveredMesh = null;
let pinnedTooltipMesh = null;
let animationId = null;
let isAnimating = true;
let isRotating = true;
let fps = 0;
let lastTime = performance.now();
let frameCount = 0;

// D3 Force Simulation (3D)
let simulation;

// Цвета по группам
const GROUP_COLORS = {
    'epoch': (node) => {
        // Градиент от красного к зеленому в зависимости от accuracy
        const acc = node.accuracy || 0;
        const r = Math.floor(255 * (1 - acc));
        const g = Math.floor(255 * acc);
        return `rgb(${r}, ${g}, 50)`;
    },
    'era': '#b388ff',        // legacy
    'platform': '#00e5ff',
    'module': '#80d8ff',
    'model': '#ffd54f',
    'pipeline': '#a7ffeb',
    'data': '#69f0ae',
    'dataset': '#69f0ae',    // backward compat (старые данные могли присылать dataset)
    'artifact': '#b0bec5',
    'training': '#ff8a80',
    'core': '#4fc3f7',       // Голубой
    'security': '#ff9800'    // Оранжевый
};

// Инициализация
async function init() {
    try {
        console.log('🚀 Starting initialization...');
        
        // Проверка наличия Three.js
        if (typeof THREE === 'undefined') {
            throw new Error('Three.js не загружен. Проверьте подключение к CDN.');
        }
        console.log('✅ Three.js loaded');
        
        // Проверка наличия D3.js
        if (typeof d3 === 'undefined') {
            throw new Error('D3.js не загружен. Проверьте подключение к CDN.');
        }
        console.log('✅ D3.js loaded');
        
        // Загрузка данных
        console.log('📊 Loading graph data...');
        const response = await fetch('/data');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        nodes = data.nodes || [];
        links = data.links || [];
        
        console.log(`✅ Loaded ${nodes.length} nodes and ${links.length} links`);
        
        if (nodes.length === 0) {
            throw new Error('Нет данных для визуализации');
        }
        
        // Обновление статистики
        updateStats();
        
        // Создание сцены
        scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0a0a0a);
        scene.fog = new THREE.Fog(0x0a0a0a, 100, 1000);
        console.log('✅ Scene created');
        
        // Камера
        camera = new THREE.PerspectiveCamera(
            75,
            window.innerWidth / window.innerHeight,
            0.1,
            10000
        );
        camera.position.set(0, 0, 500);
        console.log('✅ Camera created');
        
        // Рендерер
        renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        const container = document.getElementById('canvas-container');
        if (!container) {
            throw new Error('Canvas container not found');
        }
        container.appendChild(renderer.domElement);
        console.log('✅ Renderer created and added to DOM');
        
        // OrbitControls (для вращения, зума, панорамирования)
        // Проверяем разные варианты загрузки OrbitControls
        let OrbitControlsClass = null;
        
        if (typeof THREE !== 'undefined' && typeof THREE.OrbitControls !== 'undefined') {
            OrbitControlsClass = THREE.OrbitControls;
        } else if (typeof window.OrbitControls !== 'undefined') {
            OrbitControlsClass = window.OrbitControls;
        }
        
        if (OrbitControlsClass) {
            controls = new OrbitControlsClass(camera, renderer.domElement);
            controls.enableDamping = true;
            controls.dampingFactor = 0.05;
            controls.minDistance = 100;
            controls.maxDistance = 2000;
            controls.autoRotate = isRotating;
            controls.autoRotateSpeed = 0.5;
            console.log('✅ OrbitControls created');
        } else {
            console.warn('⚠️ OrbitControls not available, using fallback');
            // Fallback: создаем простые контролы вручную
            controls = {
                enableDamping: true,
                dampingFactor: 0.05,
                minDistance: 100,
                maxDistance: 2000,
                autoRotate: isRotating,
                autoRotateSpeed: 0.5,
                update: function() {
                    if (this.autoRotate) {
                        const angle = Date.now() * 0.0001;
                        camera.position.x = Math.cos(angle) * 500;
                        camera.position.z = Math.sin(angle) * 500;
                        camera.lookAt(0, 0, 0);
                    }
                },
                reset: function() {
                    camera.position.set(0, 0, 500);
                    camera.lookAt(0, 0, 0);
                }
            };
        }
        
        // Освещение
        const ambientLight = new THREE.AmbientLight(0x404040, 0.6);
        scene.add(ambientLight);
        
        const directionalLight1 = new THREE.DirectionalLight(0x64b5f6, 0.8);
        directionalLight1.position.set(200, 200, 200);
        scene.add(directionalLight1);
        
        const directionalLight2 = new THREE.DirectionalLight(0xff9800, 0.4);
        directionalLight2.position.set(-200, -200, -200);
        scene.add(directionalLight2);
        console.log('✅ Lighting setup complete');
        
        // Raycaster для hover/click
        raycaster = new THREE.Raycaster();
        mouse = new THREE.Vector2();
        
        // Обработчик клика по узлам (будет установлен позже в setupEventListeners)
        console.log('✅ Click handler будет установлен в setupEventListeners');
        
        // Создание узлов (шары)
        createNodes();
        console.log(`✅ Created ${nodeMeshes.length} node meshes`);
        
        // Создание связей (линии)
        createLinks();
        console.log(`✅ Created ${linkLines.length} link lines`);
        
        // D3 Force Simulation
        initForceSimulation();
        console.log('✅ Force simulation initialized');
        
        // События
        setupEventListeners();
        console.log('✅ Event listeners setup');
        
        // Скрыть загрузку
        const loadingEl = document.getElementById('loading');
        if (loadingEl) {
            loadingEl.style.display = 'none';
        }
        
        console.log('✅ Initialization complete, starting animation...');
        
        // Запуск анимации
        animate();
        
    } catch (error) {
        console.error('❌ Initialization error:', error);
        const loadingEl = document.getElementById('loading');
        if (loadingEl) {
            loadingEl.textContent = 'Ошибка: ' + error.message;
            loadingEl.style.color = '#ff4444';
        }
        // Показываем детали ошибки в консоли
        throw error;
    }
}

function createNodes() {
    nodes.forEach((node, index) => {
        // Размер шара
        const radius = (node.size || 1.0) * 5;
        
        // Геометрия и материал
        const geometry = new THREE.SphereGeometry(radius, 32, 32);
        const color = GROUP_COLORS[node.group] ? 
            (typeof GROUP_COLORS[node.group] === 'function' ? 
                GROUP_COLORS[node.group](node) : GROUP_COLORS[node.group]) : 
            '#ffffff';
        const material = new THREE.MeshStandardMaterial({
            color: color,
            metalness: 0.3,
            roughness: 0.4,
            emissive: color,
            emissiveIntensity: 0.2
        });
        
        const mesh = new THREE.Mesh(geometry, material);
        
        // Позиция из данных или случайная
        mesh.position.set(
            node.x || (Math.random() - 0.5) * 500,
            node.y || (Math.random() - 0.5) * 500,
            node.z || (Math.random() - 0.5) * 500
        );
        
        // Сохранение данных узла в mesh
        mesh.userData = { node: node, index: index };

        // Постоянная подпись для ключевых узлов (чтобы было видно "что есть что" без ховера)
        const alwaysLabelGroups = new Set(['era', 'platform', 'module', 'model', 'training', 'data', 'dataset']);
        if (alwaysLabelGroups.has(node.group)) {
            const labelColor =
                node.group === 'era' ? '#b388ff' :
                node.group === 'model' ? '#ffd54f' :
                node.group === 'platform' ? '#00e5ff' :
                node.group === 'training' ? '#ff8a80' :
                node.group === 'data' || node.group === 'dataset' ? '#69f0ae' :
                '#ffffff';
            const label = createTextSprite(node.label || node.id, labelColor);
            label.position.set(0, (node.size || 1.0) * 8, 0);
            mesh.add(label);
            mesh.userData.labelSprite = label;
        }
        
        // Добавление в сцену
        scene.add(mesh);
        nodeMeshes.push(mesh);
    });
}

function createLinks() {
    links.forEach(link => {
        const sourceIndex = nodes.findIndex(n => n.id === link.source);
        const targetIndex = nodes.findIndex(n => n.id === link.target);
        
        if (sourceIndex === -1 || targetIndex === -1) return;
        
        const sourceMesh = nodeMeshes[sourceIndex];
        const targetMesh = nodeMeshes[targetIndex];
        
        if (!sourceMesh || !targetMesh) return;
        
        // Создание линии
        const geometry = new THREE.BufferGeometry().setFromPoints([
            sourceMesh.position.clone(),
            targetMesh.position.clone()
        ]);
        
        const material = new THREE.LineBasicMaterial({
            color: getLinkColor(link.type),
            opacity: 0.3,
            transparent: true,
            linewidth: 2
        });
        
        const line = new THREE.Line(geometry, material);
        scene.add(line);
        
        linkLines.push({
            line: line,
            source: sourceMesh,
            target: targetMesh,
            link: link
        });
    });
}

function getLinkColor(type) {
    const colors = {
        'epoch_chain': 0x64b5f6,
        'era_transition': 0xb388ff,
        'belongs_to': 0x7c4dff,
        'contains': 0x00e5ff,
        'uses': 0xffd54f,
        'depends_on': 0xa7ffeb,
        'has_data': 0x69f0ae,
        'has_artifact': 0xb0bec5,
        'has_experiment': 0xff8a80,
        'produces': 0xffab91,
        'feeds': 0x66bb6a,
        'pipeline': 0x90a4ae,
        'data_flow': 0x4fc3f7,
        'resource': 0x90caf9,
        'security': 0xff9800,
        'training_start': 0x66bb6a
    };
    return colors[type] || 0xffffff;
}

function createTextSprite(text, color = '#ffffff') {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const padding = 16;
    ctx.font = 'bold 28px Arial';
    const metrics = ctx.measureText(text);
    const textWidth = Math.ceil(metrics.width);
    const w = textWidth + padding * 2;
    const h = 52;
    canvas.width = w;
    canvas.height = h;

    // background pill
    ctx.fillStyle = 'rgba(0,0,0,0.55)';
    ctx.strokeStyle = 'rgba(255,255,255,0.15)';
    ctx.lineWidth = 2;
    const r = 14;
    ctx.beginPath();
    ctx.moveTo(r, 2);
    ctx.lineTo(w - r, 2);
    ctx.quadraticCurveTo(w - 2, 2, w - 2, r);
    ctx.lineTo(w - 2, h - r);
    ctx.quadraticCurveTo(w - 2, h - 2, w - r, h - 2);
    ctx.lineTo(r, h - 2);
    ctx.quadraticCurveTo(2, h - 2, 2, h - r);
    ctx.lineTo(2, r);
    ctx.quadraticCurveTo(2, 2, r, 2);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();

    // text
    ctx.font = 'bold 28px Arial';
    ctx.fillStyle = color;
    ctx.textBaseline = 'middle';
    ctx.fillText(text, padding, h / 2);

    const texture = new THREE.CanvasTexture(canvas);
    texture.minFilter = THREE.LinearFilter;
    const material = new THREE.SpriteMaterial({ map: texture, transparent: true });
    const sprite = new THREE.Sprite(material);

    // scale in world units
    const scale = 0.6;
    sprite.scale.set((w / 100) * 80 * scale, (h / 100) * 80 * scale, 1);
    return sprite;
}

function initForceSimulation() {
    // D3 Force Simulation (2D с добавлением Z координаты)
    // D3 не поддерживает 3D напрямую, используем 2D и добавляем Z
    simulation = d3.forceSimulation(nodes)
        .force('charge', d3.forceManyBody().strength(-1000))
        .force('link', d3.forceLink(links).id(d => d.id).distance(100).strength(0.1))
        .force('center', d3.forceCenter(0, 0))
        .force('collision', d3.forceCollide().radius(d => (d.size || 1.0) * 5 + 10))
        .on('tick', updatePositions);
    
    // Начальные позиции для D3
    nodes.forEach((node, i) => {
        if (!node.x) node.x = (Math.random() - 0.5) * 500;
        if (!node.y) node.y = (Math.random() - 0.5) * 500;
        if (!node.z) node.z = (Math.random() - 0.5) * 500;
    });
    
    // Кастомная 3D симуляция: обновляем Z координату на основе связей
    simulation.on('tick', () => {
        // Простая симуляция Z: узлы стремятся к среднему Z своих соседей
        nodes.forEach(node => {
            const neighbors = links
                .filter(l => l.source.id === node.id || l.target.id === node.id)
                .map(l => l.source.id === node.id ? l.target : l.source);
            
            if (neighbors.length > 0) {
                const avgZ = neighbors.reduce((sum, n) => sum + (n.z || 0), 0) / neighbors.length;
                node.z = node.z * 0.9 + avgZ * 0.1;  // Плавное движение к среднему
            }
        });
    });
}

function updatePositions() {
    // Обновление позиций узлов из D3 simulation
    nodes.forEach((node, i) => {
        if (nodeMeshes[i]) {
            nodeMeshes[i].position.set(node.x, node.y, node.z);
        }
    });
    
    // Обновление связей
    linkLines.forEach(linkLine => {
        const points = [
            linkLine.source.position.clone(),
            linkLine.target.position.clone()
        ];
        linkLine.line.geometry.setFromPoints(points);
    });
}

function animate() {
    animationId = requestAnimationFrame(animate);
    
    if (isAnimating) {
        // Обновление D3 simulation
        simulation.tick();
        
        // Вращение камеры (если включено)
        if (isRotating && controls && controls.autoRotate) {
            if (typeof controls.update === 'function') {
                controls.update();
            }
        }
        
        // Пульсация узлов по loss (для эпох)
        nodeMeshes.forEach(mesh => {
            if (mesh.userData.node.group === 'epoch') {
                const loss = mesh.userData.node.loss || 1.0;
                const scale = 1.0 + Math.sin(Date.now() * 0.001) * (loss * 0.1);
                mesh.scale.set(scale, scale, scale);
            }
        });
        
        // Обновление FPS
        frameCount++;
        const now = performance.now();
        if (now - lastTime >= 1000) {
            fps = frameCount;
            frameCount = 0;
            lastTime = now;
            const fpsEl = document.getElementById('fps');
            if (fpsEl) fpsEl.textContent = fps;
        }
    }

    // Tooltip follow: если закреплён (pin) или просто hover — держим tooltip привязанным к шару
    if (pinnedTooltipMesh) {
        updateTooltipPositionForMesh(pinnedTooltipMesh);
    } else if (hoveredMesh) {
        updateTooltipPositionForMesh(hoveredMesh);
    }
    
    renderer.render(scene, camera);
}

function setupEventListeners() {
    // Mouse move / click — только по canvas (чтобы клики по overlay/кнопкам не сбивали выбор)
    renderer.domElement.addEventListener('mousemove', onMouseMove);
    renderer.domElement.addEventListener('click', onMouseClick);
    
    // Resize
    window.addEventListener('resize', onWindowResize);
    
    // Drag для изменения симуляции
    let isDragging = false;
    renderer.domElement.addEventListener('mousedown', () => {
        isDragging = true;
        simulation.alphaTarget(0.3).restart();
    });
    renderer.domElement.addEventListener('mouseup', () => {
        isDragging = false;
        simulation.alphaTarget(0);
    });
}

function onMouseMove(event) {
    // если tooltip закреплён кликом — hover не меняем
    if (pinnedTooltipMesh) return;

    mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
    mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;
    
    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(nodeMeshes);
    
    if (intersects.length > 0) {
        const mesh = intersects[0].object;
        hoveredMesh = mesh;
        showTooltipAtMesh(mesh);
        
        // Подсветка
        if (selectedNode !== mesh) {
            nodeMeshes.forEach(m => {
                m.material.emissiveIntensity = 0.2;
            });
            mesh.material.emissiveIntensity = 0.8;
        }
    } else {
        hoveredMesh = null;
        hideTooltip();
        if (selectedNode) {
            selectedNode.material.emissiveIntensity = 0.2;
            selectedNode = null;
        }
    }
}

function onMouseClick(event) {
    // Обновляем координаты мыши
    mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
    mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;
    
    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(nodeMeshes);
    
    if (intersects.length > 0) {
        const mesh = intersects[0].object;
        const node = mesh.userData.node;
        
        // Если кликнули по уже выбранному узлу - открываем расширенную панель
        if (selectedNode === mesh) {
            showExpandedPanel(node);
            return;
        }
        
        selectedNode = mesh;
        pinnedTooltipMesh = mesh; // закрепляем tooltip на выбранном узле
        
        // Увеличить узел
        nodeMeshes.forEach(m => {
            m.scale.set(1, 1, 1);
        });
        mesh.scale.set(1.5, 1.5, 1.5);

        // Показать tooltip “приклеенным” к шару (не к курсору)
        showTooltipAtMesh(mesh);
        
        // Логирование в консоль
        console.log('🎯 Выбран узел:', node.id);
        console.log('📌 Tooltip закреплён на узле');
        console.log('💡 Кликните ещё раз по узлу для расширенной информации');
        
        // Перезапустить симуляцию для притяжения к выбранному узлу
        simulation.alphaTarget(0.3).restart();
    } else {
        // Клик в пустое место - снимаем выбор и закрываем панель
        if (selectedNode) {
            selectedNode = null;
            pinnedTooltipMesh = null;
            nodeMeshes.forEach(m => {
                m.scale.set(1, 1, 1);
            });
            console.log('🔄 Выбор снят (клик в пустое место)');
            simulation.alphaTarget(0);
        }
        hoveredMesh = null;
        hideTooltip();
        closeExpandedPanel();
    }
}

function getScreenPositionForMesh(mesh) {
    if (!mesh || !camera) return null;
    const v = mesh.position.clone();
    v.project(camera);
    return {
        x: (v.x * 0.5 + 0.5) * window.innerWidth,
        y: (-v.y * 0.5 + 0.5) * window.innerHeight
    };
}

function updateTooltipPositionForMesh(mesh) {
    const tooltip = document.getElementById('tooltip');
    if (!tooltip || tooltip.style.display === 'none') return;
    const pos = getScreenPositionForMesh(mesh);
    if (!pos) return;
    tooltip.style.left = (pos.x + 12) + 'px';
    tooltip.style.top = (pos.y + 12) + 'px';
}

function showTooltipAtMesh(mesh) {
    if (!mesh) return;
    const pos = getScreenPositionForMesh(mesh);
    if (!pos) return;
    // Рендерим контент только при смене узла, дальше в animate() двигаем позицию
    const tooltip = document.getElementById('tooltip');
    const nodeId = mesh.userData && mesh.userData.node ? mesh.userData.node.id : '';
    const lastNodeId = tooltip ? tooltip.getAttribute('data-node-id') : null;
    const isHidden = !tooltip || tooltip.style.display === 'none';
    // Важно: если tooltip скрыт (после ухода курсора), то при повторном наведении на тот же узел
    // нужно снова отрисовать контент, иначе "описание не срабатывает".
    if (!tooltip || lastNodeId !== String(nodeId) || isHidden) {
        showTooltip(mesh.userData.node, pos.x, pos.y);
        const t = document.getElementById('tooltip');
        if (t) t.setAttribute('data-node-id', String(nodeId));
    } else {
        // только позиция
        updateTooltipPositionForMesh(mesh);
    }
}

function showTooltip(node, x, y) {
    const tooltip = document.getElementById('tooltip');
    tooltip.style.display = 'block';
    tooltip.style.left = x + 10 + 'px';
    tooltip.style.top = y + 10 + 'px';
    
    let html = `<h3>${node.label || node.id}</h3>`;
    
    // Информация об эре
    if (node.era_label) {
        html += `<div class="param"><span class="param-key">Эпоха ИИ:</span> <span class="param-value">${node.era_label}</span></div>`;
    }
    if (typeof node.year === 'number' && Number.isFinite(node.year)) {
        html += `<div class="param"><span class="param-key">Год:</span> <span class="param-value">${node.year.toFixed(1)}</span></div>`;
    } else if (node.year !== undefined && node.year !== null) {
        // fallback если год пришёл строкой/другим типом
        html += `<div class="param"><span class="param-key">Год:</span> <span class="param-value">${String(node.year)}</span></div>`;
    }
    if (node.description) {
        html += `<div class="param"><span class="param-key">Описание:</span> <span class="param-value">${node.description}</span></div>`;
    }
    
    // Параметры в зависимости от типа узла
    if (node.group === 'epoch') {
        html += `<div class="section-title">📊 Метрики обучения</div>`;
        if (node.accuracy !== undefined && node.accuracy !== null) {
            html += `<div class="param"><span class="param-key">Accuracy:</span> <span class="param-value">${(node.accuracy * 100).toFixed(2)}%</span></div>`;
        }
        if (node.train_accuracy !== undefined && node.train_accuracy !== null) {
            html += `<div class="param"><span class="param-key">Train Accuracy:</span> <span class="param-value">${(node.train_accuracy * 100).toFixed(2)}%</span></div>`;
        }
        if (node.val_accuracy !== undefined && node.val_accuracy !== null) {
            html += `<div class="param"><span class="param-key">Val Accuracy:</span> <span class="param-value">${(node.val_accuracy * 100).toFixed(2)}%</span></div>`;
        }
        if (node.loss !== undefined && node.loss !== null) {
            html += `<div class="param"><span class="param-key">Loss:</span> <span class="param-value">${node.loss.toFixed(4)}</span></div>`;
        }
        if (node.train_loss !== undefined && node.train_loss !== null) {
            html += `<div class="param"><span class="param-key">Train Loss:</span> <span class="param-value">${node.train_loss.toFixed(4)}</span></div>`;
        }
        if (node.val_loss !== undefined && node.val_loss !== null) {
            html += `<div class="param"><span class="param-key">Val Loss:</span> <span class="param-value">${node.val_loss.toFixed(4)}</span></div>`;
        }
        
        html += `<div class="section-title">🎯 Метрики классификации</div>`;
        if (node.precision !== undefined && node.precision !== null) {
            html += `<div class="param"><span class="param-key">Precision:</span> <span class="param-value">${(node.precision * 100).toFixed(2)}%</span></div>`;
        }
        if (node.recall !== undefined && node.recall !== null) {
            html += `<div class="param"><span class="param-key">Recall:</span> <span class="param-value">${(node.recall * 100).toFixed(2)}%</span></div>`;
        }
        if (node.f1_score !== undefined && node.f1_score !== null) {
            html += `<div class="param"><span class="param-key">F1 Score:</span> <span class="param-value">${(node.f1_score * 100).toFixed(2)}%</span></div>`;
        }
        
        html += `<div class="section-title">📈 ROC кривая</div>`;
        if (node.auc !== undefined && node.auc !== null) {
            html += `<div class="param"><span class="param-key">AUC:</span> <span class="param-value">${node.auc.toFixed(4)}</span></div>`;
        }
        if (node.tpr !== undefined && node.tpr !== null) {
            html += `<div class="param"><span class="param-key">TPR (Sensitivity):</span> <span class="param-value">${(node.tpr * 100).toFixed(2)}%</span></div>`;
        }
        if (node.fpr !== undefined && node.fpr !== null) {
            html += `<div class="param"><span class="param-key">FPR (1-Specificity):</span> <span class="param-value">${(node.fpr * 100).toFixed(2)}%</span></div>`;
        }
        
        // ROC кривая визуализация
        if (node.tpr !== undefined && node.fpr !== undefined && node.roc_curve) {
            html += `<div class="roc-chart-container"><canvas id="roc-chart-${node.id}" width="200" height="200"></canvas></div>`;
        }
        
        html += `<div class="section-title">⚙️ Параметры</div>`;
        if (node.lr !== undefined && node.lr !== null) {
            html += `<div class="param"><span class="param-key">Learning Rate:</span> <span class="param-value">${node.lr.toFixed(6)}</span></div>`;
        }
        if (node.batch_size !== undefined && node.batch_size !== null) {
            html += `<div class="param"><span class="param-key">Batch Size:</span> <span class="param-value">${node.batch_size}</span></div>`;
        }
        if (node.gpu_mem) {
            html += `<div class="param"><span class="param-key">GPU Memory:</span> <span class="param-value">${node.gpu_mem}</span></div>`;
        }
        if (node.time) {
            html += `<div class="param"><span class="param-key">Time:</span> <span class="param-value">${node.time}</span></div>`;
        }
        if (node.epoch !== undefined && node.epoch !== null) {
            const epochText = node.epoch_in_era ? `${node.epoch} (${node.epoch_in_era})` : node.epoch;
            html += `<div class="param"><span class="param-key">Epoch:</span> <span class="param-value">${epochText}</span></div>`;
        }
    } else if (node.group === 'era') {
        if (node.description) html += `<div class="param"><span class="param-key">Описание:</span> <span class="param-value">${node.description}</span></div>`;
        if (node.year !== undefined && node.year !== null) html += `<div class="param"><span class="param-key">Год начала:</span> <span class="param-value">${Math.floor(node.year)}</span></div>`;
    }

    // Универсальный блок: показываем details/metrics для узлов платформы/модели/датасетов и т.п.
    if (node.details && typeof node.details === 'object') {
        const escapeHtml = (s) => String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\"/g, '&quot;')
            .replace(/'/g, '&#039;');

        const renderObject = (obj, depth = 0) => {
            if (obj === null || obj === undefined) return '';
            if (depth > 2) return `<div class="param"><span class="param-value">${escapeHtml('[...]')}</span></div>`;
            if (typeof obj !== 'object') return `<span class="param-value">${escapeHtml(obj)}</span>`;
            const entries = Object.entries(obj).slice(0, 18); // ограничим шум
            let out = '';
            for (const [k, v] of entries) {
                if (v && typeof v === 'object' && !Array.isArray(v)) {
                    out += `<div class="section-title">🔎 ${escapeHtml(k)}</div>`;
                    out += renderObject(v, depth + 1);
                } else if (Array.isArray(v)) {
                    const preview = v.slice(0, 8).map(x => escapeHtml(x)).join(', ');
                    out += `<div class="param"><span class="param-key">${escapeHtml(k)}:</span> <span class="param-value">[${preview}${v.length > 8 ? ', ...' : ''}]</span></div>`;
                } else {
                    out += `<div class="param"><span class="param-key">${escapeHtml(k)}:</span> <span class="param-value">${escapeHtml(v)}</span></div>`;
                }
            }
            return out;
        };

        html += `<div class="section-title">🧾 Детали</div>`;
        html += renderObject(node.details, 0);
    }
    
    tooltip.innerHTML = html;
    
    // Рисуем ROC кривую если есть данные
    if (node.tpr !== undefined && node.fpr !== undefined) {
        setTimeout(() => {
            drawROCCurve(`roc-chart-${node.id}`, node.fpr, node.tpr, node.auc);
        }, 10);
    }
}

function drawROCCurve(canvasId, fpr, tpr, auc) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    // защитимся от битых/пустых данных (иначе будет падать на toFixed / NaN)
    if (!(typeof fpr === 'number' && Number.isFinite(fpr)) || !(typeof tpr === 'number' && Number.isFinite(tpr))) {
        return;
    }
    
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    const padding = 20;
    const plotWidth = width - 2 * padding;
    const plotHeight = height - 2 * padding;
    
    // Очистка
    ctx.clearRect(0, 0, width, height);
    
    // Фон
    ctx.fillStyle = '#1a1a2e';
    ctx.fillRect(0, 0, width, height);
    
    // Сетка
    ctx.strokeStyle = '#333';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 10; i++) {
        const x = padding + (i / 10) * plotWidth;
        const y = padding + (i / 10) * plotHeight;
        ctx.beginPath();
        ctx.moveTo(x, padding);
        ctx.lineTo(x, padding + plotHeight);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(padding + plotWidth, y);
        ctx.stroke();
    }
    
    // Диагональ (случайный классификатор)
    ctx.strokeStyle = '#666';
    ctx.lineWidth = 1;
    ctx.setLineDash([5, 5]);
    ctx.beginPath();
    ctx.moveTo(padding, padding + plotHeight);
    ctx.lineTo(padding + plotWidth, padding);
    ctx.stroke();
    ctx.setLineDash([]);
    
    // ROC кривая (упрощенная - одна точка)
    const x = padding + fpr * plotWidth;
    const y = padding + plotHeight - tpr * plotHeight;
    
    // Линия от (0,0) до точки
    ctx.strokeStyle = '#64b5f6';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(padding, padding + plotHeight);
    ctx.lineTo(x, y);
    ctx.stroke();
    
    // Точка
    ctx.fillStyle = '#64b5f6';
    ctx.beginPath();
    ctx.arc(x, y, 4, 0, Math.PI * 2);
    ctx.fill();
    
    // Подписи осей
    ctx.fillStyle = '#fff';
    ctx.font = '10px Arial';
    ctx.textAlign = 'center';
    ctx.fillText('FPR', width / 2, height - 5);
    ctx.save();
    ctx.translate(10, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('TPR', 0, 0);
    ctx.restore();
    
    // AUC
    ctx.fillStyle = '#64b5f6';
    ctx.font = 'bold 12px Arial';
    ctx.textAlign = 'right';
    const aucText = (typeof auc === 'number' && Number.isFinite(auc)) ? auc.toFixed(3) : 'N/A';
    ctx.fillText(`AUC: ${aucText}`, width - 5, 15);
}

function hideTooltip() {
    document.getElementById('tooltip').style.display = 'none';
}

function onWindowResize() {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
}

function updateStats() {
    document.getElementById('node-count').textContent = nodes.length;
    document.getElementById('link-count').textContent = links.length;
    const epochCount = nodes.filter(n => n.group === 'epoch').length;
    document.getElementById('epoch-count').textContent = epochCount;
}

// Функции управления
function resetCamera() {
    camera.position.set(0, 0, 500);
    if (controls && typeof controls.reset === 'function') {
        controls.reset();
    }
    if (controls && typeof controls.update === 'function') {
        controls.update();
    }
}

// Сохранение 3D модели
function saveModel() {
    try {
        // Сохранение данных в JSON (всегда работает)
        const data = {
            nodes: nodes,
            links: links,
            timestamp: new Date().toISOString(),
            version: '1.0',
            title: 'Эпохи развития искусственного интеллекта',
            description: '3D визуализация этапов обучения ИИ с метриками'
        };
        const output = JSON.stringify(data, null, 2);
        const blob = new Blob([output], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `ai_epochs_model_${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
        console.log('✅ Данные модели сохранены');
        if (typeof addLog === 'function') {
            addLog('✅ Данные модели сохранены как JSON', 'success');
        }
    } catch (error) {
        console.error('❌ Ошибка сохранения модели:', error);
        if (typeof addLog === 'function') {
            addLog('❌ Ошибка сохранения модели: ' + error.message, 'error');
        }
    }
}

function toggleAnimation() {
    isAnimating = !isAnimating;
    if (isAnimating) {
        animate();
    } else {
        if (animationId) cancelAnimationFrame(animationId);
    }
}

function toggleRotation() {
    isRotating = !isRotating;
    if (controls) {
        controls.autoRotate = isRotating;
    }
}

// Функция для показа расширенной панели
function showExpandedPanel(node) {
    const panel = document.getElementById('expanded-panel');
    const backdrop = document.getElementById('overlay-backdrop');
    const content = document.getElementById('expanded-content');
    
    if (!panel || !backdrop || !content) {
        console.error('❌ Expanded panel elements not found');
        return;
    }
    
    let html = `<h2>${node.label || node.id}</h2>`;
    
    // Основные метрики в карточках
    if (node.group === 'epoch') {
        html += `<div class="metrics-grid">`;
        if (node.accuracy !== undefined) {
            html += `<div class="metric-card">
                <div class="metric-label">Accuracy</div>
                <div class="metric-value">${(node.accuracy * 100).toFixed(2)}%</div>
            </div>`;
        }
        if (node.precision !== undefined) {
            html += `<div class="metric-card">
                <div class="metric-label">Precision</div>
                <div class="metric-value">${(node.precision * 100).toFixed(2)}%</div>
            </div>`;
        }
        if (node.recall !== undefined) {
            html += `<div class="metric-card">
                <div class="metric-label">Recall</div>
                <div class="metric-value">${(node.recall * 100).toFixed(2)}%</div>
            </div>`;
        }
        if (node.f1_score !== undefined) {
            html += `<div class="metric-card">
                <div class="metric-label">F1 Score</div>
                <div class="metric-value">${(node.f1_score * 100).toFixed(2)}%</div>
            </div>`;
        }
        if (node.auc !== undefined) {
            html += `<div class="metric-card">
                <div class="metric-label">AUC</div>
                <div class="metric-value">${node.auc.toFixed(4)}</div>
            </div>`;
        }
        if (node.loss !== undefined) {
            html += `<div class="metric-card">
                <div class="metric-label">Loss</div>
                <div class="metric-value">${node.loss.toFixed(4)}</div>
            </div>`;
        }
        html += `</div>`;
        
        // ROC кривая
        if (node.roc_curve && node.roc_curve.length > 0) {
            html += `<div class="section">
                <h3>📈 ROC Curve (AUC: ${node.auc ? node.auc.toFixed(4) : 'N/A'})</h3>
                <div class="roc-chart-large">
                    <canvas id="roc-chart-expanded" width="600" height="600"></canvas>
                </div>
            </div>`;
        }
        
        // Метрики обучения
        html += `<div class="section">
            <h3>📊 Метрики обучения</h3>`;
        if (node.train_accuracy !== undefined && node.train_accuracy !== null) {
            html += `<div class="param-row">
                <span class="param-key">Train Accuracy:</span>
                <span class="param-value">${(node.train_accuracy * 100).toFixed(2)}%</span>
            </div>`;
        }
        if (node.val_accuracy !== undefined && node.val_accuracy !== null) {
            html += `<div class="param-row">
                <span class="param-key">Val Accuracy:</span>
                <span class="param-value">${(node.val_accuracy * 100).toFixed(2)}%</span>
            </div>`;
        }
        if (node.train_loss !== undefined && node.train_loss !== null) {
            html += `<div class="param-row">
                <span class="param-key">Train Loss:</span>
                <span class="param-value">${node.train_loss.toFixed(4)}</span>
            </div>`;
        }
        if (node.val_loss !== undefined && node.val_loss !== null) {
            html += `<div class="param-row">
                <span class="param-key">Val Loss:</span>
                <span class="param-value">${node.val_loss.toFixed(4)}</span>
            </div>`;
        }
        html += `</div>`;
        
        // Параметры обучения
        html += `<div class="section">
            <h3>⚙️ Параметры обучения</h3>`;
        if (node.epoch !== undefined) {
            html += `<div class="param-row">
                <span class="param-key">Epoch:</span>
                <span class="param-value">${node.epoch}${node.epoch_in_era ? ` (${node.epoch_in_era})` : ''}</span>
            </div>`;
        }
        if (node.era_label) {
            html += `<div class="param-row">
                <span class="param-key">Эпоха ИИ:</span>
                <span class="param-value">${node.era_label}</span>
            </div>`;
        }
        if (node.year !== undefined) {
            html += `<div class="param-row">
                <span class="param-key">Год:</span>
                <span class="param-value">${node.year.toFixed(1)}</span>
            </div>`;
        }
        if (node.lr !== undefined) {
            html += `<div class="param-row">
                <span class="param-key">Learning Rate:</span>
                <span class="param-value">${node.lr.toFixed(6)}</span>
            </div>`;
        }
        if (node.batch_size !== undefined) {
            html += `<div class="param-row">
                <span class="param-key">Batch Size:</span>
                <span class="param-value">${node.batch_size}</span>
            </div>`;
        }
        if (node.gpu_mem) {
            html += `<div class="param-row">
                <span class="param-key">GPU Memory:</span>
                <span class="param-value">${node.gpu_mem}</span>
            </div>`;
        }
        if (node.time) {
            html += `<div class="param-row">
                <span class="param-key">Time:</span>
                <span class="param-value">${node.time}</span>
            </div>`;
        }
        html += `</div>`;
    }
    
    content.innerHTML = html;
    panel.classList.add('visible');
    backdrop.classList.add('visible');
    
    // Рисуем ROC кривую
    if (node.roc_curve && node.roc_curve.length > 0) {
        setTimeout(() => {
            drawROCCurveExpanded('roc-chart-expanded', node.roc_curve, node.auc);
        }, 100);
    }
}

function closeExpandedPanel() {
    const panel = document.getElementById('expanded-panel');
    const backdrop = document.getElementById('overlay-backdrop');
    if (panel) panel.classList.remove('visible');
    if (backdrop) backdrop.classList.remove('visible');
}

function drawROCCurveExpanded(canvasId, rocPoints, auc) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    const padding = 40;
    const chartWidth = width - 2 * padding;
    const chartHeight = height - 2 * padding;
    
    // Очистка
    ctx.clearRect(0, 0, width, height);
    
    // Фон
    ctx.fillStyle = 'rgba(10, 10, 20, 0.8)';
    ctx.fillRect(0, 0, width, height);
    
    // Сетка
    ctx.strokeStyle = 'rgba(100, 150, 255, 0.2)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 10; i++) {
        const y = padding + (chartHeight / 10) * i;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(width - padding, y);
        ctx.stroke();
        
        const x = padding + (chartWidth / 10) * i;
        ctx.beginPath();
        ctx.moveTo(x, padding);
        ctx.lineTo(x, height - padding);
        ctx.stroke();
    }
    
    // Диагональ (случайный классификатор)
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
    ctx.lineWidth = 2;
    ctx.setLineDash([5, 5]);
    ctx.beginPath();
    ctx.moveTo(padding, height - padding);
    ctx.lineTo(width - padding, padding);
    ctx.stroke();
    ctx.setLineDash([]);
    
    // ROC кривая
    ctx.strokeStyle = '#64b5f6';
    ctx.fillStyle = 'rgba(100, 181, 246, 0.2)';
    ctx.lineWidth = 3;
    ctx.beginPath();
    
    const points = rocPoints.map(p => ({
        x: padding + p.fpr * chartWidth,
        y: height - padding - p.tpr * chartHeight
    }));
    
    ctx.moveTo(points[0].x, points[0].y);
    for (let i = 1; i < points.length; i++) {
        ctx.lineTo(points[i].x, points[i].y);
    }
    
    // Заливка под кривой
    ctx.lineTo(width - padding, height - padding);
    ctx.lineTo(padding, height - padding);
    ctx.closePath();
    ctx.fill();
    ctx.stroke();
    
    // Подписи осей
    ctx.fillStyle = '#ffffff';
    ctx.font = '14px Arial';
    ctx.textAlign = 'center';
    ctx.fillText('False Positive Rate (1 - Specificity)', width / 2, height - 10);
    
    ctx.save();
    ctx.translate(15, height / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('True Positive Rate (Sensitivity)', 0, 0);
    ctx.restore();
    
    // Подписи значений
    ctx.font = '10px Arial';
    ctx.textAlign = 'right';
    for (let i = 0; i <= 10; i++) {
        const value = (i / 10).toFixed(1);
        const y = height - padding - (chartHeight / 10) * i;
        ctx.fillText(value, padding - 5, y + 3);
        
        const x = padding + (chartWidth / 10) * i;
        ctx.textAlign = 'center';
        ctx.fillText(value, x, height - padding + 15);
        ctx.textAlign = 'right';
    }
    
    // AUC текст
    ctx.fillStyle = '#64b5f6';
    ctx.font = 'bold 16px Arial';
    ctx.textAlign = 'left';
    ctx.fillText(`AUC = ${auc ? auc.toFixed(4) : 'N/A'}`, padding + 10, padding + 25);
}

// Инициализация при загрузке (если еще не инициализировано)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
        console.log('DOM loaded, waiting for scripts...');
    });
} else {
    // Если DOM уже загружен, ждем немного для загрузки скриптов
    setTimeout(function() {
        if (typeof init === 'function') {
            init().catch(err => {
                console.error('Error in init:', err);
            });
        }
    }, 100);
}
