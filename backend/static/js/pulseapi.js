// PulseAPI Observability Frontend Engine

function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

const csrftoken = getCookie('csrftoken');

// Manual Check Execution Trigger
async function triggerManualCheck(monitorId, buttonElement) {
  const originalHtml = buttonElement.innerHTML;
  buttonElement.disabled = true;
  buttonElement.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span> Probing...`;

  try {
    const response = await fetch(`/api/v1/monitors/${monitorId}/check-now/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken,
      }
    });

    const data = await response.json();
    if (response.ok) {
      showToastNotification(`Check complete: ${data.outcome.toUpperCase()} (${data.response_time_ms}ms, HTTP ${data.http_status_code || 'N/A'})`, 'success');
      // If on detail page or overview, reload or dynamically update status
      setTimeout(() => {
        window.location.reload();
      }, 700);
    } else {
      showToastNotification(`Check failed: ${data.detail || 'Error executing manual probe'}`, 'danger');
      buttonElement.disabled = false;
      buttonElement.innerHTML = originalHtml;
    }
  } catch (err) {
    showToastNotification(`Network error: ${err.message}`, 'danger');
    buttonElement.disabled = false;
    buttonElement.innerHTML = originalHtml;
  }
}

// Monitor Toggle Enable/Disable
async function toggleMonitor(monitorId, toggleElement) {
  try {
    const response = await fetch(`/api/v1/monitors/${monitorId}/toggle/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken,
      }
    });
    const data = await response.json();
    if (response.ok) {
      showToastNotification(`Monitor '${data.name}' is now ${data.enabled ? 'ACTIVE' : 'PAUSED'}`, 'info');
      setTimeout(() => window.location.reload(), 500);
    }
  } catch (err) {
    showToastNotification(`Failed to toggle monitor: ${err.message}`, 'danger');
  }
}

// Toast Notification Helper
function showToastNotification(message, type = 'info') {
  let toastContainer = document.getElementById('pulse-toast-container');
  if (!toastContainer) {
    toastContainer = document.createElement('div');
    toastContainer.id = 'pulse-toast-container';
    toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
    toastContainer.style.zIndex = '9999';
    document.body.appendChild(toastContainer);
  }

  const bgBorder = type === 'success' ? 'border-success text-success' : (type === 'danger' ? 'border-danger text-danger' : 'border-info text-info');

  const toastEl = document.createElement('div');
  toastEl.className = `toast align-items-center text-bg-dark border ${bgBorder} show shadow-lg mb-2`;
  toastEl.setAttribute('role', 'alert');
  toastEl.innerHTML = `
    <div class="d-flex">
      <div class="toast-body font-mono py-2 px-3" style="font-size: 0.85rem;">
        ${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  `;

  toastContainer.appendChild(toastEl);
  setTimeout(() => {
    toastEl.classList.remove('show');
    toastEl.remove();
  }, 4500);
}

// Dynamic Header Form Rows for Create/Edit Monitor
function addHeaderRow() {
  const container = document.getElementById('custom-headers-container');
  if (!container) return;

  const index = container.children.length;
  const row = document.createElement('div');
  row.className = 'row g-2 align-items-center mb-2 header-row';
  row.innerHTML = `
    <div class="col-4">
      <input type="text" name="header_name[]" class="form-control pulse-input form-control-sm font-mono" placeholder="Header Name (e.g. Authorization)">
    </div>
    <div class="col-5">
      <input type="text" name="header_value[]" class="form-control pulse-input form-control-sm font-mono" placeholder="Header Value">
    </div>
    <div class="col-2">
      <div class="form-check">
        <input class="form-check-input" type="checkbox" name="header_secret[]" value="${index}" id="secret_${index}">
        <label class="form-check-label text-muted" style="font-size: 0.78rem;" for="secret_${index}">Secret</label>
      </div>
    </div>
    <div class="col-1 text-end">
      <button type="button" class="btn btn-sm btn-outline-danger" onclick="this.closest('.header-row').remove()">
        <i class="bi bi-trash"></i> &times;
      </button>
    </div>
  `;
  container.appendChild(row);
}
