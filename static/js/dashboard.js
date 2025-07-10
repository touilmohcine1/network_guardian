async function fetchDataAndDraw() {
    const res = await fetch('/api/data');
    const data = await res.json();
    const ctx = document.getElementById('attackChart').getContext('2d');

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['ARP Spoofing'],
            datasets: [{
                label: 'Nombre d\'attaques ARP',
                data: [data['ARP'] || 0],
                backgroundColor: ['#e74c3c'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'top'
                },
                title: {
                    display: true,
                    text: 'Répartition des attaques ARP détectées'
                }
            }
        }
    });
}

document.addEventListener('DOMContentLoaded', fetchDataAndDraw);
