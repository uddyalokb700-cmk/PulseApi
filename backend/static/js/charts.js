// PulseAPI Observability Charts Engine (Chart.js)

const PULSE_CHART_THEME = {
  cyanPrimary: '#00f2fe',
  cyanFill: 'rgba(0, 242, 254, 0.12)',
  warningColor: '#f59e0b',
  dangerColor: '#ef4444',
  successColor: '#10b981',
  slateMuted: '#94a3b8',
  gridBorder: 'rgba(56, 189, 248, 0.08)',
};

function renderLatencyTimeseriesChart(canvasId, points, warningThreshold = 500, failureThreshold = 2000) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  const labels = points.map(p => p.timestamp);
  const data = points.map(p => p.response_time_ms);

  const chartGradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 260);
  chartGradient.addColorStop(0, 'rgba(0, 242, 254, 0.28)');
  chartGradient.addColorStop(1, 'rgba(0, 242, 254, 0.0)');

  new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels.length ? labels : ['No Data'],
      datasets: [
        {
          label: 'Response Time (ms)',
          data: data.length ? data : [0],
          borderColor: PULSE_CHART_THEME.cyanPrimary,
          borderWidth: 2,
          backgroundColor: chartGradient,
          fill: true,
          tension: 0.35,
          pointBackgroundColor: PULSE_CHART_THEME.cyanPrimary,
          pointRadius: points.length > 20 ? 2 : 4,
          pointHoverRadius: 6,
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#090e1a',
          titleColor: '#ffffff',
          bodyColor: PULSE_CHART_THEME.cyanPrimary,
          borderColor: 'rgba(0, 242, 254, 0.3)',
          borderWidth: 1,
          padding: 10,
          callbacks: {
            label: function(context) {
              const point = points[context.dataIndex];
              const code = point && point.status_code ? `HTTP ${point.status_code}` : 'No response';
              return `Latency: ${context.parsed.y} ms (${code})`;
            }
          }
        }
      },
      scales: {
        x: {
          grid: { color: PULSE_CHART_THEME.gridBorder },
          ticks: { color: PULSE_CHART_THEME.slateMuted, font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          beginAtZero: true,
          grid: { color: PULSE_CHART_THEME.gridBorder },
          ticks: {
            color: PULSE_CHART_THEME.slateMuted,
            font: { family: 'JetBrains Mono', size: 10 },
            callback: value => `${value}ms`
          }
        }
      }
    }
  });
}

function renderStatusDistributionChart(canvasId, dist) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  const total = dist['2xx'] + dist['3xx'] + dist['4xx'] + dist['5xx'] + dist['errors'];

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['2xx Success', '3xx Redirect', '4xx Client Err', '5xx Server Err', 'Errors / Timeout'],
      datasets: [{
        data: total > 0 ? [dist['2xx'], dist['3xx'], dist['4xx'], dist['5xx'], dist['errors']] : [1],
        backgroundColor: total > 0 ? [
          '#10b981', // 2xx
          '#38bdf8', // 3xx
          '#f59e0b', // 4xx
          '#ef4444', // 5xx
          '#64748b', // errors
        ] : ['#1e293b'],
        borderWidth: 0,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#cbd5e1',
            font: { family: 'Inter', size: 11 },
            boxWidth: 12,
            padding: 12
          }
        },
        tooltip: {
          backgroundColor: '#090e1a',
          borderColor: 'rgba(255, 255, 255, 0.1)',
          borderWidth: 1,
          padding: 8
        }
      },
      cutout: '72%'
    }
  });
}

function renderEndpointComparisonChart(canvasId, endpoints) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  const labels = endpoints.map(e => e.name);
  const latencyData = endpoints.map(e => e.avg_latency_ms);

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels.length ? labels : ['No Endpoints'],
      datasets: [{
        label: 'Avg Latency (ms)',
        data: latencyData.length ? latencyData : [0],
        backgroundColor: 'rgba(0, 242, 254, 0.65)',
        hoverBackgroundColor: '#00f2fe',
        borderRadius: 4,
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#090e1a',
          titleColor: '#ffffff',
          bodyColor: '#00f2fe',
          borderColor: 'rgba(0, 242, 254, 0.3)',
          borderWidth: 1
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          grid: { color: PULSE_CHART_THEME.gridBorder },
          ticks: {
            color: PULSE_CHART_THEME.slateMuted,
            font: { family: 'JetBrains Mono', size: 10 },
            callback: value => `${value}ms`
          }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#f1f5f9', font: { family: 'Inter', size: 11 } }
        }
      }
    }
  });
}
