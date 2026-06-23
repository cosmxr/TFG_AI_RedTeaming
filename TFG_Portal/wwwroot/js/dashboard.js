// ============================================================
// dashboard.js — Gráficos Chart.js del Dashboard
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

(function () {
    'use strict';

    // -------------------------------------------------------
    // Paleta — consistente con redteam.css
    // -------------------------------------------------------
    const C = {
        green: '#00ff41',
        red: '#dc3545',
        yellow: '#ffaa00',
        blue: '#4488ff',
        purple: '#a78bfa',
        cyan: '#00ccff',
        text: '#666d76',
        border: 'rgba(255,255,255,0.06)',
        bg: '#1a1a1a',
    };

    const AI_TYPES = new Set([
        'PROMPT_INJECTION', 'JAILBREAK', 'SYSTEM_PROMPT_LEAKAGE',
        'DATA_EXTRACTION', 'CONTEXT_MANIPULATION', 'INDIRECT_INJECTION',
    ]);

    const LABEL_MAP = {
        PROMPT_INJECTION: 'PI',
        JAILBREAK: 'JB',
        SYSTEM_PROMPT_LEAKAGE: 'SPL',
        DATA_EXTRACTION: 'DE',
        CONTEXT_MANIPULATION: 'CM',
        INDIRECT_INJECTION: 'II',
        XSS: 'XSS',
        SQLI: 'SQLi',
        LFI: 'LFI',
        CSRF: 'CSRF',
    };

    const SEV_COLORS = {
        Alta: C.red,
        Media: C.yellow,
        Baja: C.blue,
    };

    // -------------------------------------------------------
    // Configuración global Chart.js — tema oscuro
    // -------------------------------------------------------
    Chart.defaults.color = C.text;
    Chart.defaults.borderColor = C.border;
    Chart.defaults.backgroundColor = C.bg;
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.font.size = 11;

    // -------------------------------------------------------
    // Helpers
    // -------------------------------------------------------
    function readJson(id) {
        const el = document.getElementById(id);
        if (!el) return [];
        try { return JSON.parse(el.textContent.trim()); }
        catch (e) { console.warn('[dashboard.js] JSON inválido en #' + id, e); return []; }
    }

    function destroyIfExists(canvasId) {
        const el = document.getElementById(canvasId);
        if (!el) return null;
        const prev = Chart.getChart(el);
        if (prev) prev.destroy();
        return el;
    }

    const TOOLTIP = {
        backgroundColor: '#1a1a1a',
        borderColor: C.border,
        borderWidth: 1,
        titleColor: C.green,
        bodyColor: '#e8e8e8',
        padding: 10,
    };

    // -------------------------------------------------------
    // Datos (leídos una sola vez)
    // -------------------------------------------------------
    const dataDia = readJson('data-ataques-por-dia');
    const dataTipo = readJson('data-ataques-por-tipo');
    const dataSev = readJson('data-ataques-por-severidad');

    // -------------------------------------------------------
    // GRÁFICO DE LÍNEA — Actividad último mes (con relleno de días vacíos)
    // -------------------------------------------------------
    function initChartLinea() {
        const canvas = destroyIfExists('chartLinea');
        if (!canvas || dataDia.length === 0) return;

        // Formatear Date → "dd/MM" con padding garantizado (sin depender de locale)
        function formatFecha(date) {
            const d = String(date.getDate()).padStart(2, '0');
            const m = String(date.getMonth() + 1).padStart(2, '0');
            return `${d}/${m}`;
        }

        // Parsear "dd/MM" → Date (año actual)
        function parseFecha(ddMM) {
            const [d, m] = ddMM.split('/').map(Number);
            return new Date(new Date().getFullYear(), m - 1, d);
        }

        // Normalizar claves del backend (por si vienen sin padding: "9/6" → "09/06")
        const dataMap = new Map(
            dataDia.map(d => {
                const [dd, mm] = d.Fecha.split('/');
                const key = dd.padStart(2, '0') + '/' + mm.padStart(2, '0');
                return [key, d.Total];
            })
        );

        // Rango: fecha más antigua del dataset → hoy
        const fechasOrdenadas = dataDia
            .map(d => parseFecha(formatFecha(parseFecha(d.Fecha)))) // normaliza antes de comparar
            .sort((a, b) => a - b);

        const inicio = fechasOrdenadas[0];
        const hoy = new Date(); hoy.setHours(0, 0, 0, 0);

        const labels = [];
        const valores = [];

        for (let cur = new Date(inicio); cur <= hoy; cur.setDate(cur.getDate() + 1)) {
            const key = formatFecha(cur);
            labels.push(key);
            valores.push(dataMap.get(key) ?? 0);
        }

        new Chart(canvas, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Ataques',
                    data: valores,
                    borderColor: C.green,
                    backgroundColor: 'rgba(0,255,65,0.08)',
                    borderWidth: 2,
                    pointBackgroundColor: C.green,
                    pointBorderColor: C.bg,
                    pointBorderWidth: 2,
                    pointRadius: ctx => valores[ctx.dataIndex] > 0 ? 4 : 0,
                    pointHoverRadius: 6,
                    tension: 0.4,
                    fill: true,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        ...TOOLTIP,
                        filter: item => item.raw > 0,
                        callbacks: {
                            title: items => 'Fecha: ' + items[0].label,
                            label: item => ' ' + item.raw + ' ataques',
                        },
                    },
                },
                scales: {
                    x: {
                        grid: { color: C.border },
                        ticks: {
                            color: C.text,
                            maxTicksLimit: 15,
                            maxRotation: 0,
                        },
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: C.border },
                        ticks: {
                            color: C.text,
                            stepSize: 1,
                            callback: v => Number.isInteger(v) ? v : null,
                        },
                    },
                },
            },
        });
    }

    // -------------------------------------------------------
    // GRÁFICO DE BARRAS — Ataques por tipo
    // -------------------------------------------------------
    function initChartBarras() {
        const canvas = destroyIfExists('chartBarras');
        if (!canvas || dataTipo.length === 0) return;

        const colores = dataTipo.map(d =>
            AI_TYPES.has(d.TipoAtaque) ? C.yellow : C.green
        );

        new Chart(canvas, {
            type: 'bar',
            data: {
                labels: dataTipo.map(d => LABEL_MAP[d.TipoAtaque] || d.TipoAtaque),
                datasets: [{
                    label: 'Ataques',
                    data: dataTipo.map(d => d.Total),
                    backgroundColor: colores.map(c => c + '33'),
                    borderColor: colores,
                    borderWidth: 1,
                    borderRadius: 3,
                    borderSkipped: false,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        ...TOOLTIP,
                        callbacks: {
                            label: item => ' ' + item.raw + ' ataques',
                        },
                    },
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: C.text },
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: C.border },
                        ticks: {
                            color: C.text,
                            stepSize: 1,
                            callback: v => Number.isInteger(v) ? v : null,
                        },
                    },
                },
            },
        });
    }

    // -------------------------------------------------------
    // GRÁFICO DONUT — Distribución de severidad
    // -------------------------------------------------------
    function initChartDonut() {
        const canvas = destroyIfExists('chartDonut');
        if (!canvas || dataSev.length === 0) return;

        const colors = dataSev.map(d => SEV_COLORS[d.Severidad] || '#888888');

        new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: dataSev.map(d => d.Severidad),
                datasets: [{
                    data: dataSev.map(d => d.Total),
                    backgroundColor: colors.map(c => c + '33'),
                    borderColor: colors,
                    borderWidth: 2,
                    hoverOffset: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        ...TOOLTIP,
                        callbacks: {
                            label: ctx => ` ${ctx.label}: ${ctx.parsed}`,
                        },
                    },
                },
            },
        });

        const legend = document.getElementById('legend-donut');
        if (!legend) return;
        legend.innerHTML = '';
        dataSev.forEach((d, i) => {
            const item = document.createElement('div');
            item.className = 'donut-legend-item';
            item.innerHTML =
                `<span class="donut-legend-dot" style="background:${colors[i]};"></span>` +
                `<span>${d.Severidad}: <strong>${d.Total}</strong></span>`;
            legend.appendChild(item);
        });
    }

    // -------------------------------------------------------
    // Init
    // -------------------------------------------------------
    document.addEventListener('DOMContentLoaded', function () {
        initChartLinea();
        initChartBarras();
        initChartDonut();
    });

}());