const socket = io();

const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Packet Size', data: [], backgroundColor: 'rgba(75, 192, 192, 0.6)' }] },
    options: {
        scales: {
            x: { ticks: { color: 'white' }, grid: { color: 'rgba(255, 255, 255, 0.2)' } },
            y: { ticks: { color: 'white' }, grid: { color: 'rgba(255, 255, 255, 0.2)' } }
        },
        plugins: { legend: { labels: { color: 'white' } } }
    }
});

const lineCtx = document.getElementById('lineChart').getContext('2d');
const lineChart = new Chart(lineCtx, {
    type: 'line',
    data: { labels: [], datasets: [{ label: 'Packet Size Over Time', data: [], borderColor: 'rgba(136, 11, 38, 0.6)', fill: true, backgroundColor: 'rgba(136, 11, 38, 0.2)' }] },
    options: {
        scales: {
            x: { ticks: { color: 'white' }, grid: { color: 'rgba(255, 255, 255, 0.2)' } },
            y: { ticks: { color: 'white' }, grid: { color: 'rgba(255, 255, 255, 0.2)' } }
        },
        plugins: { legend: { labels: { color: 'white' } } }
    }
});

const protocolCtx = document.getElementById('protocolChart').getContext('2d');
const protocolChart = new Chart(protocolCtx, {
    type: 'pie',
    data: { labels: [], datasets: [{ label: 'Protocol Distribution', data: [], backgroundColor: ['#F50039', '#168EDF', '#FFB700', '#1B5050'] }] },
    options: {
        plugins: { legend: { labels: { color: 'white' } } }
    }
});

const tableBody = document.getElementById('trafficTable');
let packetData = [];

socket.on('new_packet', (data) => {
    packetData.push(data);
    if (packetData.length > 20) {
        packetData.shift();
    }

    updateTable();
    updateCharts();
});

function updateTable() {
    tableBody.innerHTML = "";
    packetData.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${row.timestamp}</td><td>${row.source}</td><td>${row.destination}</td><td>${row.protocol}</td><td>${row.size}</td>`;
        tableBody.appendChild(tr);
    });
}

function updateCharts() {
    const labels = packetData.map(row => row.timestamp);
    const sizes = packetData.map(row => row.size);

    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = sizes;
    trafficChart.update();

    lineChart.data.labels = labels;
    lineChart.data.datasets[0].data = sizes;
    lineChart.update();

    const protocolCounts = {};
    packetData.forEach(row => {
        protocolCounts[row.protocol] = (protocolCounts[row.protocol] || 0) + 1;
    });

    protocolChart.data.labels = Object.keys(protocolCounts);
    protocolChart.data.datasets[0].data = Object.values(protocolCounts);
    protocolChart.update();
}

// Navigate back to home page
document.getElementById('backBtn').addEventListener('click', function () {
    window.location.href = '/';
});
