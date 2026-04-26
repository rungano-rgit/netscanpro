let currentScanId = null;
let pollingInterval = null;

document.addEventListener('DOMContentLoaded', () => {
    loadStatistics();
    attachEventListeners();
});

function attachEventListeners() {
    const startBtn = document.getElementById('start-scan-btn');
    if (startBtn) startBtn.addEventListener('click', startScan);
    
    const exportCsv = document.getElementById('export-csv-btn');
    const exportJson = document.getElementById('export-json-btn');
    const viewHistory = document.getElementById('view-history-btn');
    const closeHistory = document.getElementById('close-history-btn');
    
    if (exportCsv) exportCsv.addEventListener('click', () => exportResults('csv'));
    if (exportJson) exportJson.addEventListener('click', () => exportResults('json'));
    if (viewHistory) viewHistory.addEventListener('click', loadHistory);
    if (closeHistory) closeHistory.addEventListener('click', () => {
        document.getElementById('history-card').style.display = 'none';
    });
}

async function loadStatistics() {
    try {
        const res = await fetch('/api/stats');
        const stats = await res.json();
        document.getElementById('total-scans').textContent = stats.total_scans || 0;
        document.getElementById('total-devices').textContent = stats.total_devices || 0;
        document.getElementById('blocked-devices').textContent = stats.blocked_devices || 0;
        document.getElementById('last-scan').textContent = stats.last_scan ? new Date(stats.last_scan).toLocaleString() : 'Never';
    } catch(e) { console.error(e); }
}

async function startScan() {
    const target = document.getElementById('target-input').value;
    const timeout = parseInt(document.getElementById('timeout').value);
    
    if (!target) {
        alert('Please enter a target IP range');
        return;
    }
    
    const startBtn = document.getElementById('start-scan-btn');
    startBtn.disabled = true;
    startBtn.innerHTML = '<span class="spinner"></span> Starting Scan...';
    
    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, timeout })
        });
        const data = await res.json();
        
        if (res.ok) {
            currentScanId = data.scan_id;
            showProgressCard();
            startPolling();
        } else {
            alert(data.error || 'Failed to start scan');
            resetStartButton();
        }
    } catch(e) {
        alert('Error: ' + e.message);
        resetStartButton();
    }
}

function resetStartButton() {
    const btn = document.getElementById('start-scan-btn');
    btn.disabled = false;
    btn.innerHTML = '🚀 Start Network Scan';
}

function showProgressCard() {
    document.getElementById('progress-card').style.display = 'block';
    document.getElementById('results-card').style.display = 'none';
    document.getElementById('history-card').style.display = 'none';
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('progress-percent').textContent = '0';
    document.getElementById('scanned-count').textContent = '0';
    document.getElementById('active-count').textContent = '0';
}

function startPolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    
    pollingInterval = setInterval(async () => {
        if (!currentScanId) return;
        
        try {
            const res = await fetch(`/api/scan/${currentScanId}/status`);
            const data = await res.json();
            
            if (data.error) {
                stopPolling();
                resetStartButton();
                return;
            }
            
            if (data.progress !== undefined) {
                document.getElementById('progress-fill').style.width = `${data.progress}%`;
                document.getElementById('progress-percent').textContent = Math.round(data.progress);
            }
            
            if (data.active_count !== undefined) {
                document.getElementById('active-count').textContent = data.active_count;
            }
            
            if (data.status === 'complete') {
                stopPolling();
                await loadResults(currentScanId);
                resetStartButton();
                loadStatistics();
            }
        } catch(e) {
            console.error(e);
            stopPolling();
            resetStartButton();
        }
    }, 1500);
}

function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

async function loadResults(scanId) {
    try {
        const res = await fetch(`/api/scan/${scanId}/results`);
        const data = await res.json();
        if (res.ok && data.results) {
            displayResults(data.results);
        }
    } catch(e) { console.error(e); }
}

function displayResults(results) {
    document.getElementById('progress-card').style.display = 'none';
    document.getElementById('results-card').style.display = 'block';
    
    const tbody = document.getElementById('results-body');
    tbody.innerHTML = '';
    
    if (!results || results.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center">No active devices found</td></tr>';
        document.getElementById('results-summary').innerHTML = 'No devices discovered.';
        return;
    }
    
    const windowsCount = results.filter(d => d.os && d.os.includes('Windows')).length;
    const linuxCount = results.filter(d => d.os && d.os.includes('Linux')).length;
    
    document.getElementById('results-summary').innerHTML = `
        <strong>📊 Summary:</strong> Found ${results.length} active device(s) | 
        🪟 Windows: ${windowsCount} | 🐧 Linux/Unix: ${linuxCount}
    `;
    
    results.forEach(device => {
        const row = tbody.insertRow();
        row.insertCell(0).innerHTML = `<strong>${device.ip}</strong>`;
        row.insertCell(1).innerHTML = '<span class="status-active">● Active</span>';
        row.insertCell(2).textContent = device.response_time || '<1ms';
        row.insertCell(3).textContent = device.hostname || 'Unknown';
        let osIcon = device.os && device.os.includes('Windows') ? '🪟' : (device.os && device.os.includes('Linux') ? '🐧' : '💻');
        row.insertCell(4).textContent = `${osIcon} ${device.os || 'Unknown'}`;
    });
}

async function exportResults(format) {
    if (!currentScanId) {
        alert('No scan results to export');
        return;
    }
    window.open(`/api/export/${currentScanId}?format=${format}`, '_blank');
}

async function loadHistory() {
    try {
        const res = await fetch('/api/history');
        const history = await res.json();
        
        document.getElementById('history-card').style.display = 'block';
        document.getElementById('results-card').style.display = 'none';
        
        const container = document.getElementById('history-list');
        container.innerHTML = '';
        
        if (!history || history.length === 0) {
            container.innerHTML = '<p class="text-center">No scan history</p>';
            return;
        }
        
        history.forEach(scan => {
            const div = document.createElement('div');
            div.style.cssText = 'padding: 12px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;';
            div.innerHTML = `
                <div>
                    <strong>🎯 ${scan.target_range}</strong><br>
                    <small>📅 ${new Date(scan.timestamp).toLocaleString()} | 📱 ${scan.device_count} devices | ⏱️ ${scan.duration ? scan.duration.toFixed(1) : '?'}s</small>
                </div>
                <div>
                    <button class="btn btn-sm btn-outline" onclick="viewHistoryScan('${scan.scan_id}')">View</button>
                    <button class="btn btn-sm btn-outline" onclick="deleteHistoryScan('${scan.scan_id}')" style="color:#dc2626;">Delete</button>
                </div>
            `;
            container.appendChild(div);
        });
    } catch(e) { console.error(e); }
}

window.viewHistoryScan = async (scanId) => {
    currentScanId = scanId;
    await loadResults(scanId);
    document.getElementById('history-card').style.display = 'none';
};

window.deleteHistoryScan = async (scanId) => {
    if (confirm('Delete this scan?')) {
        await fetch(`/api/history/${scanId}`, { method: 'DELETE' });
        loadHistory();
        loadStatistics();
    }
};