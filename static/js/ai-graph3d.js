/* global ForceGraph3D */

async function fetchGraphData() {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 20000);
  try {
    const r = await fetch('/api/ai/graph3d/data', { signal: controller.signal, cache: 'no-store' });
    const j = await r.json();
    if (!j || !j.success) throw new Error(j?.error || 'graph data failed');
    return j.graph;
  } finally {
    clearTimeout(t);
  }
}

function nodeColor(n) {
  if (n.group === 'model') return '#4f46e5';
  if (n.group === 'run') return n.status === 'completed' ? '#16a34a' : '#f59e0b';
  if (n.group === 'epoch') {
    const va = typeof n.val_accuracy === 'number' ? n.val_accuracy : null;
    if (va === null) return '#94a3b8';
    // green for better accuracy
    const g = Math.max(0, Math.min(255, Math.round(50 + va * 205)));
    return `rgb(34, ${g}, 94)`;
  }
  return '#64748b';
}

function nodeLabel(n) {
  const title = `${n.label || n.id}`;
  const lines = [`<b>${title}</b>`];
  if (n.group === 'run') {
    if (n.status) lines.push(`Статус: ${n.status === 'completed' ? 'завершено' : n.status}`);
    if (typeof n.best_accuracy === 'number') lines.push(`Лучшая точность: ${(n.best_accuracy * 100).toFixed(2)}%`);
  }
  if (n.group === 'epoch') {
    if (typeof n.epoch === 'number') lines.push(`Эпоха: ${n.epoch}`);
    if (typeof n.train_loss === 'number') lines.push(`Потери (train): ${n.train_loss.toFixed(4)}`);
    if (typeof n.val_loss === 'number') lines.push(`Потери (val): ${n.val_loss.toFixed(4)}`);
    if (typeof n.train_accuracy === 'number') lines.push(`Точность (train): ${(n.train_accuracy * 100).toFixed(2)}%`);
    if (typeof n.val_accuracy === 'number') lines.push(`Точность (val): ${(n.val_accuracy * 100).toFixed(2)}%`);
  }
  return lines.join('<br/>');
}

async function init() {
  const el = document.getElementById('graph3d');
  const statusEl = document.getElementById('graph-status');
  if (!el) return;

  try {
    statusEl.textContent = 'Загрузка библиотек...';
    const t0 = Date.now();
    while (Date.now() - t0 < 12000) {
      if (typeof ForceGraph3D === 'function') break;
      await new Promise((r) => setTimeout(r, 120));
    }
    if (typeof ForceGraph3D !== 'function') throw new Error('3D библиотеки не загрузились (провайдер/CDN). Перезагрузи страницу.');

    statusEl.textContent = 'Загрузка данных обучения...';
    const graphData = await fetchGraphData();

    if (!graphData.nodes.length) {
      statusEl.textContent = 'Нет данных обучения. Запусти обучение в разделе “🎓 Обучение”.';
      return;
    }

    statusEl.textContent = `Узлов: ${graphData.nodes.length}, связей: ${graphData.links.length}`;

    // Ensure the graph uses the container size (fixes "bottom-right" rendering / wrong viewport)
    const getSize = () => ({
      w: Math.max(320, el.clientWidth || 0),
      h: Math.max(420, el.clientHeight || 0),
    });

    const Graph = ForceGraph3D()(el)
      .backgroundColor('#0b1220')
      .width(getSize().w)
      .height(getSize().h)
      .graphData(graphData)
      .nodeLabel(nodeLabel)
      .nodeColor(nodeColor)
      .nodeRelSize(5)
      .linkColor((l) => (l.type === 'next' ? 'rgba(148,163,184,0.65)' : 'rgba(99,102,241,0.55)'))
      .linkOpacity(0.65)
      .linkWidth((l) => (l.type === 'next' ? 1 : 1.6))
      .onNodeClick((node) => {
        // Aim camera at node
        const dist = 160;
        const ratio = 1 + dist / Math.hypot(node.x, node.y, node.z);
        Graph.cameraPosition(
          { x: node.x * ratio, y: node.y * ratio, z: node.z * ratio },
          node,
          900
        );
      });

    // keep sizing in sync (container resize / responsive layout)
    try {
      const ro = new ResizeObserver(() => {
        const s = getSize();
        Graph.width(s.w);
        Graph.height(s.h);
        Graph.zoomToFit(300, 60);
      });
      ro.observe(el);
    } catch (_) {
      // Safari/older browsers fallback
      window.addEventListener('resize', () => {
        const s = getSize();
        Graph.width(s.w);
        Graph.height(s.h);
        Graph.zoomToFit(300, 60);
      }, { passive: true });
    }

    // nice initial view (after first tick)
    setTimeout(() => Graph.zoomToFit(800, 60), 250);
  } catch (e) {
    console.error(e);
    if (statusEl) statusEl.textContent = `Ошибка 3D: ${e.message}`;
  }
}

document.addEventListener('DOMContentLoaded', init);


