async function fetchDataAndDraw() {
    const res = await fetch('/api/data');
    const data = await res.json();
    const ctx = document.getElementById('attackChart').getContext('2d');

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(data),
            datasets: [{
                label: 'Nombre d\'attaques',
                data: Object.values(data),
                backgroundColor: ['#e74c3c', '#f1c40f', '#2ecc71', '#3498db'],
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
                    text: 'Répartition des attaques détectées'
                }
            }
        }
    });
}

document.addEventListener('DOMContentLoaded', fetchDataAndDraw);
