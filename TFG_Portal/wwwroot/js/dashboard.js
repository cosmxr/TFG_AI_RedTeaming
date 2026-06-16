// ============================================================
// dashboard.js — Gráficos Chart.js del Dashboard
// AI Red Teaming Platform - TFG Ingeniería Informática
//
// Lee los datos JSON embebidos por el servidor en la vista
// y construye los gráficos con la paleta visual del portal.
// ============================================================

(function () {
    'use strict';

    // Paleta — consistente con redteam.css
    const C = {
        green: '#00ff41',
        red: '#ff4444',
        yellow: '#ffaa00',
        blue: '#4488ff',
        purple: '#aa44ff',
        cyan: '#00ccff',
        text: '#888888',
        border: '#2e2e2e',
        bg: '#1a1a1a',
    };

    // Colores para las barras (uno por tipo de ataque, cíclico)
    const BAR_COLORS = [C.green, C.red, C.yellow, C.blue, C.purple, C.cyan];

    // -------------------------------------------------------
    // Configuración global de Chart.js — tema oscuro
    // -------------------------------------------------------
    Chart.defaults.color = C.text;
    Chart.defaults.borderColor = C.border;
    Chart.defaults.backgroundColor = C.bg;
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.font.size = 11;

    // -------------------------------------------------------
    // Leer datos JSON embebidos en la vista
    // Se usa <script type="application/json"> para evitar XSS
    // -------------------------------------------------------
    function leerJson(id) {
        const el = document.getElementById(id);
        if (!el) return [];
        try { return JSON.parse(el.textContent.trim()); }
        catch (e) { console.warn('[dashboard.js] Error JSON en', id, e); return []; }
    }

    const datosPorTipo = leerJson('data-ataques-por-tipo');
    const datosPorDia = leerJson('data-ataques-por-dia');

    // -------------------------------------------------------
    // Configuración compartida de tooltips
    // -------------------------------------------------------
    const tooltipDefaults = {
        backgroundColor: '#1a1a1a',
        borderColor: C.border,
        borderWidth: 1,
        titleColor: C.green,
        bodyColor: '#e8e8e8',
        padding: 10,
    };

    // -------------------------------------------------------
    // GRÁFICO DE LÍNEA — Actividad último mes
    // -------------------------------------------------------
    function initChartLinea() {
        const canvas = document.getElementById('chartLinea');
        if (!canvas) return;

        const serie30Dias = construirSerieUltimos30Dias(datosPorDia || []);
        const labels = serie30Dias.map(d => d.label);
        const valores = serie30Dias.map(d => d.total);

        new Chart(canvas, {
            type: 'line',
            data: {
                labels,
                datasets: [{
                    label: 'Ataques',
                    data: valores,
                    borderColor: C.green,
                    backgroundColor: 'rgba(0, 255, 65, 0.08)',
                    borderWidth: 2,
                    pointBackgroundColor: C.green,
                    pointBorderColor: C.bg,
                    pointBorderWidth: 2,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    tension: 0.35,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        ...tooltipDefaults,
                        callbacks: {
                            title: items => 'Fecha: ' + serie30Dias[items[0].dataIndex].fechaCompleta,
                            label: item => ' ' + item.raw + ' ataques'
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: C.border },
                        ticks: {
                            color: C.text,
                            maxTicksLimit: 6
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: C.border },
                        ticks: {
                            color: C.text,
                            stepSize: 1,
                            callback: v => Number.isInteger(v) ? v : null
                        }
                    }
                }
            }
        });
    }

    function construirSerieUltimos30Dias(datos) {
        const hoy = new Date();
        hoy.setHours(0, 0, 0, 0);

        const mapa = new Map();

        datos.forEach(d => {
            const key = normalizarFechaKey(d.Fecha);
            mapa.set(key, d.Total);
        });

        const serie = [];

        for (let i = 29; i >= 0; i--) {
            const fecha = new Date(hoy);
            fecha.setDate(hoy.getDate() - i);

            const key = normalizarFechaKey(fecha);
            const total = mapa.get(key) ?? 0;

            serie.push({
                key,
                total,
                label: fecha.toLocaleDateString('es-ES', {
                    day: '2-digit',
                    month: '2-digit'
                }),
                fechaCompleta: fecha.toLocaleDateString('es-ES', {
                    day: '2-digit',
                    month: '2-digit',
                    year: 'numeric'
                })
            });
        }

        return serie;
    }

    function normalizarFechaKey(fecha) {
        const d = new Date(fecha);
        d.setHours(0, 0, 0, 0);
        return d.toISOString().slice(0, 10);
    }

    // -------------------------------------------------------
    // GRÁFICO DE BARRAS — Ataques por tipo
    // -------------------------------------------------------
    function initChartBarras() {
        const canvas = document.getElementById('chartBarras');
        if (!canvas || datosPorTipo.length === 0) return;

        const colores = datosPorTipo.map((_, i) => BAR_COLORS[i % BAR_COLORS.length]);

        new Chart(canvas, {
            type: 'bar',
            data: {
                labels: datosPorTipo.map(d => d.TipoAtaque),
                datasets: [{
                    label: 'Ataques',
                    data: datosPorTipo.map(d => d.Total),
                    backgroundColor: colores.map(c => c + '33'), // 20% opacidad
                    borderColor: colores,
                    borderWidth: 1,
                    borderRadius: 3,
                    borderSkipped: false,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        ...tooltipDefaults,
                        callbacks: { label: item => ' ' + item.raw + ' ataques' }
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: C.text }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: C.border },
                        ticks: {
                            color: C.text,
                            stepSize: 1,
                            callback: v => Number.isInteger(v) ? v : null
                        }
                    }
                }
            }
        });
    }

    // -------------------------------------------------------
    // Init al cargar el DOM
    // -------------------------------------------------------
    document.addEventListener('DOMContentLoaded', function () {
        initChartLinea();
        initChartBarras();
    });

})();
