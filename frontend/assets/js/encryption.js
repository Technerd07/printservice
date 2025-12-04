'use strict';

/**
 * Encryption Dashboard Frontend Module
 * Handles UI interactions and communicates with backend /api/upload
 * NO Node.js code here — browser-only APIs
 */

(function() {
  const MAX_FILES = 5;
  const MAX_FILE_SIZE = 10 * 1024 * 1024;
  const ALLOWED_TYPES = new Set([
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ]);

  // DOM references
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const btnBrowse = document.getElementById('btnBrowse');
  const filesList = document.getElementById('filesList');
  const status = document.getElementById('status');
  const encryptForm = document.getElementById('encryptForm');
  const btnEncrypt = document.getElementById('btnEncrypt');

  let selectedFiles = [];
  let isProcessing = false;

  // ==========================================
  // Browse Button Handler (MAIN FIX)
  // ==========================================

  if (btnBrowse && fileInput) {
    btnBrowse.addEventListener('click', (e) => {
      e.preventDefault();
      console.log('Browse button clicked');
      fileInput.click(); // Opens native file picker ✓
    });
  }

  // ==========================================
  // File Input Handler
  // ==========================================

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      console.log('Files selected:', e.target.files.length);
      addFiles(e.target.files);
    });
  }

  // ==========================================
  // Drag & Drop Handlers
  // ==========================================

  if (dropzone) {
    // Show hover state on drag enter
    dropzone.addEventListener('dragenter', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('hover');
    });

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('hover');
    });

    // Remove hover on drag leave
    dropzone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (e.target === dropzone) {
        dropzone.classList.remove('hover');
      }
    });

    // Handle drop
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('hover');
      
      if (e.dataTransfer && e.dataTransfer.files) {
        console.log('Files dropped:', e.dataTransfer.files.length);
        addFiles(e.dataTransfer.files);
      }
    });

    // Keyboard accessibility
    dropzone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });
  }

  // ==========================================
  // File Validation & Addition
  // ==========================================

  function addFiles(files) {
    if (isProcessing) return;

    const incoming = Array.from(files);
    const errors = [];
    const validFiles = [];

    for (const file of incoming) {
      let error = null;

      // Type validation
      if (!file.type || !ALLOWED_TYPES.has(file.type)) {
        error = `${escapeHtml(file.name)}: unsupported file type`;
      }
      // Size validation
      else if (file.size > MAX_FILE_SIZE) {
        error = `${escapeHtml(file.name)}: exceeds 10 MB limit`;
      }
      // Filename validation
      else if (!file.name || file.name.length > 260 || file.name.includes('\0')) {
        error = `${escapeHtml(file.name)}: invalid filename`;
      }
      // Duplicate check
      else if (selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
        error = `${escapeHtml(file.name)}: already selected`;
      }
      // Max files check
      else if (selectedFiles.length + validFiles.length >= MAX_FILES) {
        error = `Maximum ${MAX_FILES} files allowed`;
        break;
      }

      if (error) {
        errors.push(error);
      } else {
        validFiles.push(file);
      }
    }

    // Show errors
    if (errors.length > 0) {
      status.textContent = '⚠ ' + errors.slice(0, 3).join('; ');
      status.style.color = '#ff6b6b';
    }

    // Add valid files
    if (validFiles.length > 0) {
      selectedFiles.push(...validFiles);
      status.textContent = `✓ ${selectedFiles.length} file(s) selected`;
      status.style.color = '#0fb5a5';
    }

    renderFiles();
  }

  // ==========================================
  // Render File List
  // ==========================================

  function renderFiles() {
    filesList.innerHTML = '';
    
    if (selectedFiles.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'muted small';
      empty.textContent = 'No files selected';
      filesList.appendChild(empty);
      return;
    }

    selectedFiles.forEach((file, idx) => {
      const el = document.createElement('div');
      el.className = 'file-item';

      const meta = document.createElement('div');
      meta.className = 'file-meta';

      const nameEl = document.createElement('strong');
      nameEl.className = 'file-name';
      nameEl.textContent = file.name;

      const sizeEl = document.createElement('span');
      sizeEl.className = 'muted small';
      sizeEl.textContent = `(${formatBytes(file.size)})`;

      meta.appendChild(nameEl);
      meta.appendChild(sizeEl);

      const btnDiv = document.createElement('div');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn-ghost small';
      btn.setAttribute('data-idx', String(idx));
      btn.setAttribute('aria-label', `Remove file ${file.name}`);
      btn.textContent = 'Remove';

      btn.addEventListener('click', (e) => {
        e.preventDefault();
        selectedFiles.splice(idx, 1);
        renderFiles();
        status.textContent = '';
      });

      btnDiv.appendChild(btn);
      el.appendChild(meta);
      el.appendChild(btnDiv);
      filesList.appendChild(el);
    });
  }

  // ==========================================
  // Form Submission (Upload & Encrypt)
  // ==========================================

  if (encryptForm) {
    encryptForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      if (isProcessing) return;
      isProcessing = true;

      status.textContent = '';
      status.style.color = '#666';

      try {
        // Validate files
        if (selectedFiles.length === 0) {
          throw new Error('Please upload at least one file.');
        }

        // Validate pages
        const totalPages = Number(document.getElementById('totalPages').value) || 0;
        if (!Number.isInteger(totalPages) || totalPages < 1 || totalPages > 10000) {
          throw new Error('Please enter valid total pages (1–10000).');
        }

        // Validate print type
        const printType = document.querySelector('input[name="printType"]:checked')?.value;
        if (!['bw', 'color'].includes(printType)) {
          throw new Error('Invalid print type selected.');
        }

        // Validate binding
        const binding = document.querySelector('input[name="binding"]:checked')?.value;
        if (!['none', 'soft', 'hard'].includes(binding)) {
          throw new Error('Invalid binding type selected.');
        }

        // Get notes
        const notes = document.getElementById('notes').value.trim().slice(0, 500);

        // Update button
        btnEncrypt.disabled = true;
        btnEncrypt.textContent = 'Uploading & Encrypting...';

        // Build FormData
        const formData = new FormData();
        selectedFiles.forEach(file => formData.append('files', file));
        formData.append('totalPages', String(totalPages));
        formData.append('printType', printType);
        formData.append('binding', binding);
        formData.append('notes', notes);

        // POST to backend (same-origin, so /api/upload works)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 min timeout

        const response = await fetch('/api/upload', {
          method: 'POST',
          body: formData,
          headers: {
            'Accept': 'application/json'
          },
          signal: controller.signal,
          credentials: 'same-origin'
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.error || `Upload failed (${response.status})`);
        }

        const data = await response.json();

        // Validate response
        if (!data.success || !data.job || !data.job.jobId) {
          throw new Error('Invalid server response. Please try again.');
        }

        const jobId = String(data.job.jobId);
        if (!/^[a-f0-9]{32}$/.test(jobId)) {
          throw new Error('Invalid job ID received from server.');
        }

        // Store order data in session
        const orderData = {
          jobId,
          timestamp: Date.now(),
          totalPages,
          printType,
          binding,
          notes,
          fileCount: selectedFiles.length
        };
        sessionStorage.setItem('enc_order_data', btoa(JSON.stringify(orderData)));

        status.textContent = `✓ Files encrypted successfully. Job ID: ${jobId}`;
        status.style.color = '#0fb5a5';
        btnEncrypt.textContent = 'Encrypt and Place Order';

        // Redirect after brief delay
        setTimeout(() => {
          window.location.href = './Orderpage.html';
        }, 1500);

      } catch (err) {
        console.error('[Encryption] Error:', err);
        status.textContent = `✗ Error: ${err.message}`;
        status.style.color = '#ff6b6b';
        btnEncrypt.textContent = 'Encrypt and Place Order';
        btnEncrypt.disabled = false;
        isProcessing = false;
      }
    });
  }

  // ==========================================
  // Utility Functions
  // ==========================================

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  }

  // ==========================================
  // Initialization
  // ==========================================

  renderFiles();
  console.log('✓ Encryption dashboard module loaded');
})();