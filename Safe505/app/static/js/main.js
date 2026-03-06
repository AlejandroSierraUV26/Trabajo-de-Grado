// main.js - Lógica del Frontend para AWS Security Monitor

document.addEventListener("DOMContentLoaded", function() {
    console.log("Sistema cargado y listo.");

    // 1. Auto-cierre de alertas flash después de 5 segundos
    // AHORA IGNORA LAS QUE TENGAN LA CLASE '.alerta-permanente'
    setTimeout(function() {
        let alerts = document.querySelectorAll('.alert:not(.alerta-permanente)');
        alerts.forEach(function(alert) {
            let bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // 2. Validar si estamos en la página del Dashboard (si existe chartData)
    const chartDataElement = document.getElementById('chartData');
    
    if (chartDataElement) {
        // Extraer los datos de Jinja pasados a través del HTML
        const chartLabels = JSON.parse(chartDataElement.getAttribute('data-labels') || '[]');
        const chartValoresFailed = JSON.parse(chartDataElement.getAttribute('data-valores-failed') || '[]');
        const chartValoresPassed = JSON.parse(chartDataElement.getAttribute('data-valores-passed') || '[]');
        
        const countCritical = parseInt(chartDataElement.getAttribute('data-critical')) || 0;
        const countHigh = parseInt(chartDataElement.getAttribute('data-high')) || 0;
        const countMedium = parseInt(chartDataElement.getAttribute('data-medium')) || 0;
        const countLow = parseInt(chartDataElement.getAttribute('data-low')) || 0;

        // Nuevos datos para la gráfica de servicios
        const serviciosLabels = JSON.parse(chartDataElement.getAttribute('data-servicios-labels') || '[]');
        const serviciosValores = JSON.parse(chartDataElement.getAttribute('data-servicios-valores') || '[]');

        // Gráfica Histórica (Líneas)
        const ctxHistory = document.getElementById('historyChart');
        if (ctxHistory) {
            new Chart(ctxHistory.getContext('2d'), {
                type: 'line',
                data: {
                    labels: chartLabels,
                    datasets: [
                        {
                            label: 'Vulnerabilidades (FAILED)',
                            data: chartValoresFailed,
                            borderColor: '#dc3545',
                            backgroundColor: 'rgba(220, 53, 69, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointBackgroundColor: '#dc3545'
                        },
                        {
                            label: 'Controles Seguros (PASSED)',
                            data: chartValoresPassed,
                            borderColor: '#198754',
                            backgroundColor: 'rgba(25, 135, 84, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4,
                            pointBackgroundColor: '#198754'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { y: { beginAtZero: true } },
                    plugins: { legend: { position: 'top' } } 
                }
            });
        }

        // Gráfica de Severidad (Dona)
        const ctxSeverity = document.getElementById('severityChart');
        if (ctxSeverity) {
            new Chart(ctxSeverity.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Crítico', 'Alto', 'Medio', 'Bajo'],
                    datasets: [{
                        data: [countCritical, countHigh, countMedium, countLow],
                        backgroundColor: ['#d13212', '#ff9900', '#f6c65b', '#879196'], 
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '75%',
                    plugins: { legend: { position: 'bottom' } }
                }
            });
        }

        // Gráfica de Servicios (Barras)
        const ctxService = document.getElementById('serviceChart');
        if (ctxService) {
            new Chart(ctxService.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: serviciosLabels,
                    datasets: [{
                        label: 'Vulnerabilidades Encontradas',
                        data: serviciosValores,
                        backgroundColor: '#0d6efd',
                        borderRadius: 4,
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: { 
                        y: { 
                            beginAtZero: true,
                            ticks: { precision: 0 } 
                        } 
                    },
                    plugins: { legend: { display: false } } 
                }
            });
        }
    }
});

// Función global para abrir el modal desde los onclick de la tabla HTML
window.mostrarDetalle = function(controlId, titulo) {
    const chartDataElement = document.getElementById('chartData');
    if(!chartDataElement) return;

    // Extraemos la información de los controles dinámicamente
    const infoControles = JSON.parse(chartDataElement.getAttribute('data-info') || '{}');
    
    const detalles = infoControles[controlId] || {
        descripcion: 'Descripción no disponible para este control.',
        remediacion: 'Consulte la documentación oficial de AWS o CIS Benchmark.'
    };
    
    document.getElementById('modalTitulo').innerText = `${controlId} - ${titulo}`;
    document.getElementById('modalDescripcion').innerText = detalles.descripcion;
    document.getElementById('modalRemediacion').innerText = detalles.remediacion;
    
    const modal = new bootstrap.Modal(document.getElementById('modalDetalle'));
    modal.show();
};