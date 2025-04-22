// Theme Toggle functionality
const themeToggle = document.getElementById("theme-toggle");
const prefersDarkScheme = window.matchMedia("(prefers-color-scheme: dark)");

// Check for saved theme preference or use the system preference
if (localStorage.getItem("theme") === "dark" || (!localStorage.getItem("theme") && prefersDarkScheme.matches)) {
  document.body.classList.add("dark");
  themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
} else {
  themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
}

themeToggle.addEventListener("click", () => {
  document.body.classList.toggle("dark");
  
  if (document.body.classList.contains("dark")) {
    localStorage.setItem("theme", "dark");
    themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
  } else {
    localStorage.setItem("theme", "light");
    themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
  }
});

// Tab navigation
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

tabButtons.forEach(button => {
  button.addEventListener('click', () => {
    const target = button.dataset.target;
    
    // Update active tab button
    tabButtons.forEach(btn => btn.classList.remove('active'));
    button.classList.add('active');
    
    // Show target tab content
    tabContents.forEach(content => {
      content.classList.remove('active');
      if (content.id === target) {
        content.classList.add('active');
      }
    });
  });
});

// Error Toast with improved animation
function showToast(message, type = 'error') {
  const toast = document.getElementById("error-message");
  if (!toast) return;
  
  toast.innerText = message;
  toast.style.display = "block";
  toast.style.opacity = '1';
  
  // Change color based on type
  if (type === 'success') {
    toast.style.backgroundColor = 'var(--success)';
  } else if (type === 'error') {
    toast.style.backgroundColor = 'var(--danger)';
  } else if (type === 'info') {
    toast.style.backgroundColor = 'var(--info)';
  }
  
  // Clear any existing timeout
  if (toast.timeoutId) {
    clearTimeout(toast.timeoutId);
  }
  
  // Set new timeout
  toast.timeoutId = setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => {
      toast.style.display = "none";
    }, 300);
  }, 5000);
}

// Function to show error messages from API
function showError(message) {
  showToast(message, 'error');
}

// Improved clipboard functionality
async function copyToClipboard(id) {
  try {
    const el = document.getElementById(id);
    if (!el) throw new Error("Element not found");
    
    const text = el.innerText || el.value || "";
    
    if (!text.trim()) {
      showToast("Nothing to copy", "info");
      return;
    }
    
    await navigator.clipboard.writeText(text);
    showToast("Copied to clipboard", "success");
  } catch (err) {
    showToast("Failed to copy: " + err.message, "error");
  }
}

// Button loading state helper
function setButtonLoading(buttonId, isLoading) {
  const button = document.getElementById(buttonId);
  if (!button) {
    console.error(`Button with ID ${buttonId} not found`);
    return;
  }
  
  // Store the original text directly on the button element if not already stored
  if (isLoading && !button.hasAttribute('data-original-text')) {
    button.setAttribute('data-original-text', button.innerHTML);
  }
  
  if (isLoading) {
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span> Processing...';
  } else {
    button.disabled = false;
    button.innerHTML = button.getAttribute('data-original-text') || 'Button';
  }
}

// Generate key and IV - properly connected to backend
async function generateKeyIv(prefix) {
  try {
    const sizeDropdown = document.getElementById(`${prefix}-key-size`);
    const bits = sizeDropdown ? parseInt(sizeDropdown.value) : 256;
    
    const [keyRes, ivRes] = await Promise.all([
      fetch(`/generate-key?bits=${bits}`),
      fetch('/generate-iv')
    ]);

    const keyData = await keyRes.json();
    const ivData = await ivRes.json();

    document.getElementById(`${prefix}-key`).value = keyData.key;
    document.getElementById(`${prefix}-iv`).value = ivData.iv;
    
    showToast("Key and IV generated successfully", "success");
  } catch (err) {
    showToast("Failed to generate key or IV from backend.", "error");
  }
}

// Text encryption with proper backend connection
async function encryptText() {
  const key = document.getElementById('text-key')?.value?.trim() || '';
  const iv = document.getElementById('text-iv')?.value?.trim() || '';
  const text = document.getElementById('text-input')?.value?.trim() || '';
  
  // Input validation
  if (!key) {
    showToast("Please enter or generate a key", "error");
    document.getElementById('text-key')?.focus();
    return;
  }
  
  if (!text) {
    showToast("Please enter text to encrypt", "error");
    document.getElementById('text-input')?.focus();
    return;
  }
  
  try {
    const res = await fetch('/encrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: document.getElementById('text-mode').value,
        key: document.getElementById('text-key').value,
        iv: document.getElementById('text-iv').value,
        text: document.getElementById('text-input').value
      })
    });

    const data = await res.json();
    if (!res.ok) return showError(data.detail || "Unknown error during encryption");

    document.getElementById('encrypt-output').innerText = data.ciphertext;
    showToast("Text encrypted successfully", "success");
  } catch (err) {
    showError("Network or internal error occurred.");
  }
}

// Text decryption with proper backend connection
async function decryptText() {
  const key = document.getElementById('text-dec-key')?.value?.trim() || '';
  const iv = document.getElementById('text-dec-iv')?.value?.trim() || '';
  const ciphertext = document.getElementById('text-input-dec')?.value?.trim() || '';
  
  // Input validation
  if (!key) {
    showToast("Please enter or generate a key", "error");
    document.getElementById('text-dec-key')?.focus();
    return;
  }
  
  if (!ciphertext) {
    showToast("Please enter text to decrypt", "error");
    document.getElementById('text-input-dec')?.focus();
    return;
  }
  
  try {
    const res = await fetch('/decrypt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: document.getElementById('text-mode-dec').value,
        key: document.getElementById('text-dec-key').value,
        iv: document.getElementById('text-dec-iv').value,
        text: document.getElementById('text-input-dec').value
      })
    });

    const data = await res.json();
    if (!res.ok) return showError(data.detail || "Unknown error during decryption");

    document.getElementById('decrypt-output').innerText = data.plaintext;
    showToast("Text decrypted successfully", "success");
  } catch (err) {
    showError("Network or internal error occurred.");
  }
}

// File encryption with proper backend connection
async function encryptFile() {
  const fileInput = document.getElementById('file-input');
  const key = document.getElementById('file-key')?.value?.trim() || '';
  const iv = document.getElementById('file-iv')?.value?.trim() || '';
  
  // Input validation
  if (!key) {
    showToast("Please enter or generate a key", "error");
    document.getElementById('file-key')?.focus();
    return;
  }
  
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showToast("Please select a file to encrypt", "error");
    return;
  }
  
  try {
    const formData = new FormData();
    formData.append('mode', document.getElementById('file-mode').value);
    formData.append('key', document.getElementById('file-key').value);
    formData.append('iv', document.getElementById('file-iv').value);
    formData.append('file', document.getElementById('file-input').files[0]);
    
    const res = await fetch('/encrypt-file', { method: 'POST', body: formData });

    if (res.ok) {
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'encrypted_output.enc';
      
      if (!window.encryptionDownloadTriggered) {
        window.encryptionDownloadTriggered = true;
        a.click();
        setTimeout(() => window.encryptionDownloadTriggered = false, 3000);
      }
      
      showToast("File encrypted successfully", "success");
    } else {
      showError("File encryption failed. Check key/IV or file content.");
    }
  } catch (err) {
    showError(`File encryption failed: ${err.message}`);
  }
}

// File decryption with proper backend connection
async function decryptFile() {
  const fileInput = document.getElementById('file-input-dec');
  const key = document.getElementById('file-dec-key')?.value?.trim() || '';
  const iv = document.getElementById('file-dec-iv')?.value?.trim() || '';
  
  // Input validation
  if (!key) {
    showToast("Please enter or generate a key", "error");
    document.getElementById('file-dec-key')?.focus();
    return;
  }
  
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    showToast("Please select a file to decrypt", "error");
    return;
  }
  
  try {
    const formData = new FormData();
    formData.append('mode', document.getElementById('file-mode-dec').value);
    formData.append('key', document.getElementById('file-dec-key').value);
    formData.append('iv', document.getElementById('file-dec-iv').value);
    formData.append('file', document.getElementById('file-input-dec').files[0]);
    
    const res = await fetch('/decrypt-file', { method: 'POST', body: formData });

    if (res.ok) {
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'decrypted_output.txt';
      a.click();
      
      showToast("File decrypted successfully", "success");
    } else {
      showError("File decryption failed. Check input data or parameters.");
    }
  } catch (err) {
    showError(`File decryption failed: ${err.message}`);
  }
}

// File upload handling with visual feedback
function setupFileInputs() {
  const fileInputs = document.querySelectorAll('.file-input');
  
  fileInputs.forEach(input => {
    const dropArea = input.parentElement;
    const nameDisplay = dropArea.querySelector('span');
    
    // Display filename when selected
    input.addEventListener('change', () => {
      if (input.files && input.files[0]) {
        const fileName = input.files[0].name;
        nameDisplay.textContent = fileName;
        dropArea.classList.add('file-selected');
      } else {
        nameDisplay.textContent = 'Choose a file or drag it here';
        dropArea.classList.remove('file-selected');
      }
    });
    
    // Handle drag and drop
    ['dragenter', 'dragover'].forEach(eventName => {
      dropArea.addEventListener(eventName, e => {
        e.preventDefault();
        dropArea.classList.add('drag-over');
      });
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
      dropArea.addEventListener(eventName, e => {
        e.preventDefault();
        dropArea.classList.remove('drag-over');
        
        if (eventName === 'drop') {
          input.files = e.dataTransfer.files;
          if (input.files && input.files[0]) {
            const fileName = input.files[0].name;
            nameDisplay.textContent = fileName;
            dropArea.classList.add('file-selected');
            
            // Trigger change event for compatibility
            const event = new Event('change');
            input.dispatchEvent(event);
          }
        }
      });
    });
  });
}

// Security tips modal
const securityTipsModal = document.getElementById('security-tips-modal');
const showTipsButton = document.getElementById('show-tips');
const closeTipsButton = document.getElementById('close-tips');

if (showTipsButton) {
  showTipsButton.addEventListener('click', () => {
    if (securityTipsModal) securityTipsModal.style.display = 'block';
  });
}

if (closeTipsButton) {
  closeTipsButton.addEventListener('click', () => {
    if (securityTipsModal) securityTipsModal.style.display = 'none';
  });
}

// Close modal if clicked outside of content
window.addEventListener('click', (e) => {
  if (e.target === securityTipsModal) {
    securityTipsModal.style.display = 'none';
  }
});

// Initialize everything when DOM is fully loaded
document.addEventListener('DOMContentLoaded', () => {
  // Setup the file inputs
  setupFileInputs();
  
  // Set IDs for all buttons that will use loading states
  document.querySelector('button[onclick="encryptText()"]')?.setAttribute('id', 'encrypt-text-btn');
  document.querySelector('button[onclick="decryptText()"]')?.setAttribute('id', 'decrypt-text-btn');
  document.querySelector('button[onclick="encryptFile()"]')?.setAttribute('id', 'encrypt-file-btn');
  document.querySelector('button[onclick="decryptFile()"]')?.setAttribute('id', 'decrypt-file-btn');
  document.querySelector('button[onclick="generateKeyIv(\'text\')"]')?.setAttribute('id', 'generate-key-btn');
  document.querySelector('button[onclick="generateKeyIv(\'text-dec\')"]')?.setAttribute('id', 'generate-text-dec-key-btn');
  document.querySelector('button[onclick="generateKeyIv(\'file\')"]')?.setAttribute('id', 'generate-file-key-btn');
  document.querySelector('button[onclick="generateKeyIv(\'file-dec\')"]')?.setAttribute('id', 'generate-file-dec-key-btn');
});