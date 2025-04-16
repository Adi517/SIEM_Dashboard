document.getElementById('scanBtn').addEventListener('click', function () {
    fetch('/scan')
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '';

            if (data.results.length > 0) {
                const table = document.createElement('table');
                table.classList.add('table');

                const thead = document.createElement('thead');
                thead.innerHTML = `
                    <tr>
                        <th>IP Address</th>
                        <th>Status</th>
                    </tr>
                `;
                table.appendChild(thead);

                const tbody = document.createElement('tbody');
                
                data.results.forEach(item => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${item.ip}</td>
                        <td class="${item.malicious ? 'alert' : ''}">
                            ${item.malicious ? 'Malicious' : 'Safe'}
                        </td>
                        
                    `;
                    tbody.appendChild(row);
                });

                table.appendChild(tbody);
                resultDiv.appendChild(table);
            } else {
                resultDiv.innerHTML = '<p>No results found.</p>';
            }
        })
        .catch(error => console.error('Error:', error));
});
{/* <td><pre>${JSON.stringify(item.details, null, 2)}</pre></td>
                        <th>Details</th> */}
document.getElementById('netBtn').addEventListener('click', function () {
    window.location.href = '/network_monitor';
});
document.getElementById('passBtn').addEventListener('click', function () {
    window.location.href = '/password';
});
document.getElementById('phishingBtn').addEventListener('click', function () {
    window.location.href = '/phishing';
});
document.getElementById('SystemInfo').addEventListener('click', function () {
    window.location.href = '/system';
});
