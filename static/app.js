/**
 * Log Gözcüsü - Dashboard JavaScript
 * API client and real-time updates
 */

// API Configuration
const API_BASE = window.location.origin;
const WS_BASE = API_BASE.replace('http', 'ws');

// Global state
let categoryChart = null;
let hourlyChart = null;
let ws = null;
let reconnectAttempts = 0;

// =====================================
// API Client
// =====================================

async function apiCall(endpoint) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        return null;
    }
}

// =====================================
// Status Update
// =====================================

async function updateStatus() {
    const data = await apiCall('/api/status');
    const statusEl = document.getElementById('daemon-status');
    const dot = statusEl.querySelector('.status-dot');
    const text = statusEl.querySelector('.status-text');

    if (!data) {
        dot.className = 'status-dot offline';
        text.textContent = 'API Bağlantısı Yok';
        return;
    }

    if (data.daemon_running || data.monitoring_active) {
        dot.className = 'status-dot online';
        text.textContent = 'Aktif İzleme';
    } else if (data.api_running) {
        dot.className = 'status-dot warning';
        text.textContent = 'API Açık (Daemon Kapalı)';
    } else {
        dot.className = 'status-dot offline';
        text.textContent = 'Çevrimdışı';
    }

    // Stats
    if (data.total_lines_processed !== undefined) {
        document.getElementById('total-lines').textContent = formatNumber(data.total_lines_processed);
    }

    // Uptime removed by user request

    // Last update
    document.getElementById('last-update').textContent =
        `Son güncelleme: ${new Date().toLocaleTimeString('tr-TR')}`;
}

// =====================================
// Stats Update
// =====================================

async function updateStats() {
    const data = await apiCall('/api/stats');

    if (!data) return;

    // Total threats
    document.getElementById('total-threats').textContent = formatNumber(data.total_threats || 0);

    // Critical count
    const criticalCount = (data.severity_distribution?.critical || 0) +
        (data.severity_distribution?.high || 0);
    document.getElementById('critical-count').textContent = formatNumber(criticalCount);

    // Top IPs Table
    updateTopIPs(data.top_ips || []);

    // Category Chart
    updateCategoryChart(data.categories || {});

    // Hourly Chart
    updateHourlyChart(data.hourly_distribution || {});
}

function updateTopIPs(ips) {
    const tbody = document.querySelector('#top-ips-table tbody');

    if (ips.length === 0) {
        tbody.innerHTML = '<tr><td colspan="2" class="loading">Veri yok</td></tr>';
        return;
    }

    tbody.innerHTML = ips.map(item => `
        <tr>
            <td><span class="threat-ip">${item.ip}</span></td>
            <td>${item.count}</td>
        </tr>
    `).join('');
}

// =====================================
// Charts
// =====================================

function updateCategoryChart(categories) {
    const ctx = document.getElementById('categoryChart').getContext('2d');
    const labels = Object.keys(categories);
    const values = Object.values(categories);

    const colors = [
        '#ff4757', '#ffa502', '#00d9ff', '#2ed573', '#7b2dff',
        '#ff6b81', '#ff9ff3', '#54a0ff', '#5f27cd', '#01a3a4'
    ];

    if (categoryChart) {
        categoryChart.data.labels = labels;
        categoryChart.data.datasets[0].data = values;
        categoryChart.update();
    } else {
        categoryChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors.slice(0, labels.length),
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#a0a0c0', font: { size: 11 } }
                    }
                }
            }
        });
    }
}

function updateHourlyChart(hourly) {
    const ctx = document.getElementById('hourlyChart').getContext('2d');
    const labels = Object.keys(hourly);
    const values = Object.values(hourly);

    if (hourlyChart) {
        hourlyChart.data.labels = labels;
        hourlyChart.data.datasets[0].data = values;
        hourlyChart.update();
    } else {
        hourlyChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Tehdit Sayısı',
                    data: values,
                    borderColor: '#00d9ff',
                    backgroundColor: 'rgba(0, 217, 255, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#a0a0c0' }
                    },
                    y: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#a0a0c0' }
                    }
                }
            }
        });
    }
}

// =====================================
// Threats
// =====================================

async function updateThreats() {
    const data = await apiCall('/api/threats?limit=10');

    if (!data || !data.threats) return;

    const container = document.getElementById('threats-list');

    if (data.threats.length === 0) {
        container.innerHTML = '<div class="loading">Henüz tehdit tespit edilmedi</div>';
        return;
    }

    container.innerHTML = data.threats.map(threat => `
        <div class="threat-item">
            <div class="threat-severity ${threat.severity || 'medium'}"></div>
            <div class="threat-content">
                <div class="threat-category">${threat.category || 'Unknown'}</div>
                <div class="threat-meta">
                    <span class="threat-ip">${threat.ip || 'N/A'}</span> • 
                    ${formatTime(threat.timestamp)}
                </div>
            </div>
        </div>
    `).join('');
}

function showAllThreats() {
    const modal = document.getElementById('threats-modal');
    modal.classList.add('active');

    apiCall('/api/threats?limit=100').then(data => {
        const container = document.getElementById('all-threats-list');

        if (!data || !data.threats || data.threats.length === 0) {
            container.innerHTML = '<div class="loading">Veri yok</div>';
            return;
        }

        container.innerHTML = data.threats.map((threat, index) => `
            <div class="threat-item">
                <div class="threat-severity ${threat.severity || 'medium'}"></div>
                <div class="threat-content">
                    <div class="threat-category">${threat.category || 'Unknown'}</div>
                    <div class="threat-meta">
                        <span class="threat-ip">${threat.ip || 'N/A'}</span> • 
                        ${formatTime(threat.timestamp)} •
                        ${threat.rule_id || 'N/A'}
                    </div>
                    <div class="threat-meta" style="margin-top: 4px; word-break: break-all;">
                        ${(threat.log_entry || '').substring(0, 100)}...
                    </div>
                </div>
            </div>
        `).join('');
    });
}

function closeModal() {
    document.getElementById('threats-modal').classList.remove('active');
}

// =====================================
// WebSocket - Live Logs
// =====================================

function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    try {
        ws = new WebSocket(`${WS_BASE}/api/logs/live`);

        ws.onopen = () => {
            console.log('WebSocket connected');
            reconnectAttempts = 0;
            addLogLine({ content: 'WebSocket bağlantısı kuruldu', severity: 'info' });
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);

                if (msg.type === 'log') {
                    // msg.data artık bir obje: { content, is_threat, severity ... }
                    // Eğer eski format (string) gelirse diye kontrol et
                    let entry = msg.data;
                    if (typeof entry === 'string') {
                        entry = { content: entry, is_threat: false, severity: 'normal' };
                    }
                    addLogLine(entry);
                } else if (msg.type === 'heartbeat') {
                    // Heartbeat - ignore
                }
            } catch (e) {
                console.error('WS message parse error:', e);
            }
        };

        ws.onclose = () => {
            console.log('WebSocket disconnected');
            if (reconnectAttempts < 5) {
                setTimeout(() => {
                    reconnectAttempts++;
                    connectWebSocket();
                }, 3000);
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

    } catch (e) {
        console.error('WebSocket connection failed:', e);
    }
}

function addLogLine(entry) {
    const viewer = document.getElementById('log-viewer');
    const line = document.createElement('div');

    // Sınıf belirle
    let className = 'normal';
    if (entry.is_threat) {
        className = 'attack'; // Backend tarafından tehdit olarak işaretlenmiş
    } else if (entry.severity === 'info') {
        className = 'info';
    } else {
        // Fallback: Yine de renklendirme yapmak istersen classifyLog kullanabilirsin
        // Ama kullanıcı "sadece backend belirlesin" dediği için bunu kapalı tutuyoruz
        // veya sadece basit info/warning ayrımı yapıyoruz
        if (entry.content.toLowerCase().includes('warning')) className = 'warning';
    }

    line.className = `log-line ${className}`;

    // Zaman damgası
    const timeStr = entry.timestamp ? formatTime(entry.timestamp) : new Date().toLocaleTimeString('tr-TR');
    line.textContent = `[${timeStr}] ${entry.content}`;

    viewer.appendChild(line);

    // Max 200 satır tut
    while (viewer.children.length > 200) {
        viewer.removeChild(viewer.firstChild);
    }

    // Auto scroll
    if (document.getElementById('auto-scroll').checked) {
        viewer.scrollTop = viewer.scrollHeight;
    }
}

// classifyLog artık kullanılmıyor (Backend kararına güveniyoruz)
function classifyLog_DEPRECATED(line) {
    const lower = line.toLowerCase();
    if (lower.includes('attack') || lower.includes('threat') || lower.includes('sql') || lower.includes('xss')) {
        return 'attack';
    }
    if (lower.includes('warning') || lower.includes('suspicious')) {
        return 'warning';
    }
    if (lower.includes('info') || lower.includes('debug')) {
        return 'info';
    }
    return 'normal';
}

function clearLogs() {
    const viewer = document.getElementById('log-viewer');
    viewer.innerHTML = '<div class="log-line info">Log temizlendi</div>';
}

// =====================================
// Recent Logs (Fallback)
// =====================================

async function loadRecentLogs() {
    const data = await apiCall('/api/logs/recent?limit=50');

    if (!data || !data.logs) return;

    const viewer = document.getElementById('log-viewer');
    viewer.innerHTML = '';

    data.logs.forEach(entry => {
        // API artık obje listesi dönüyor
        // Fallback (eğer string dönerse)
        if (typeof entry === 'string') {
            entry = { content: entry, is_threat: false };
        }
        addLogLine(entry);
    });
}

// =====================================
// Helpers
// =====================================

function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}d`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}s`;
    return `${Math.floor(seconds / 86400)}g`;
}

function formatTime(timestamp) {
    if (!timestamp) return 'N/A';
    try {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
    } catch {
        return timestamp;
    }
}

// =====================================
// Refresh All
// =====================================

async function refreshAll() {
    await Promise.all([
        updateStatus(),
        updateStats(),
        updateThreats()
    ]);
}

// =====================================
// Initialize
// =====================================

document.addEventListener('DOMContentLoaded', () => {
    // Initial load
    refreshAll();
    loadRecentLogs();

    // Connect WebSocket for live logs
    connectWebSocket();

    // Periodic refresh
    setInterval(refreshAll, 10000);  // Her 10 saniyede bir

    // Close modal on ESC
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });

    // Close modal on outside click
    document.getElementById('threats-modal').addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) closeModal();
    });
});
