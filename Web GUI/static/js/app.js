// VulneraPred Web Application - Main JavaScript

// DOM Elements
const codeEditor = document.getElementById('codeEditor');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const loadExampleBtn = document.getElementById('loadExampleBtn');
const uploadBtn = document.getElementById('uploadBtn');
const fileInput = document.getElementById('fileInput');
const fileInfoText = document.getElementById('fileInfoText');
const lineCount = document.getElementById('lineCount');
const charCount = document.getElementById('charCount');

const statusCards = document.getElementById('statusCards');
const statusValue = document.getElementById('statusValue');
const confidenceValue = document.getElementById('confidenceValue');
const priorityValue = document.getElementById('priorityValue');
const timeValue = document.getElementById('timeValue');

const loadingState = document.getElementById('loadingState');
const emptyState = document.getElementById('emptyState');
const resultsContainer = document.getElementById('resultsContainer');
const toast = document.getElementById('toast');

// Example vulnerable code
const EXAMPLE_CODE = `def login(username, password):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def execute_command(user_input):
    # Command Injection vulnerability
    import os
    os.system(user_input)

def load_config(data):
    # Insecure Deserialization
    import pickle
    config = pickle.loads(data)
    return config`;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkServerStatus();
    updateCodeStats();
    setupDragAndDrop();
});

// Event Listeners
codeEditor.addEventListener('input', updateCodeStats);
analyzeBtn.addEventListener('click', analyzeCode);
clearBtn.addEventListener('click', clearAll);
loadExampleBtn.addEventListener('click', loadExample);
uploadBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', handleFileUpload);

// Setup drag and drop for code editor
function setupDragAndDrop() {
    const editorWrapper = document.querySelector('.code-editor-wrapper');
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        editorWrapper.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        editorWrapper.addEventListener(eventName, () => {
            editorWrapper.style.borderColor = 'var(--neon-cyan)';
            editorWrapper.style.boxShadow = '0 0 30px rgba(6, 182, 212, 0.5)';
        });
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        editorWrapper.addEventListener(eventName, () => {
            editorWrapper.style.borderColor = '';
            editorWrapper.style.boxShadow = '';
        });
    });
    
    editorWrapper.addEventListener('drop', handleDrop);
}

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
        const file = files[0];
        // Create a file input change event manually
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);
        fileInput.files = dataTransfer.files;
        
        // Trigger the file upload handler
        handleFileUpload({ target: { files: [file] } });
    }
}

// Update code statistics
function updateCodeStats() {
    const code = codeEditor.value;
    const lines = code.split('\n').length;
    const chars = code.length;
    
    lineCount.textContent = `Lines: ${lines}`;
    charCount.textContent = `Characters: ${chars}`;
    
    if (code.trim()) {
        fileInfoText.textContent = 'Code loaded';
    } else {
        fileInfoText.textContent = 'No file loaded';
    }
}

// Check server status
async function checkServerStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        
        if (data.models_loaded) {
            analyzeBtn.disabled = false;
            showToast('Models loaded successfully', 'success');
        } else {
            analyzeBtn.disabled = true;
            showToast('Models not loaded. Please restart the server.', 'error');
        }
    } catch (error) {
        analyzeBtn.disabled = true;
        showToast('Could not connect to server', 'error');
    }
}

// Handle file upload
function handleFileUpload(event) {
    const file = event.target.files[0];
    
    if (!file) {
        return;
    }
    
    // Check file extension
    const fileName = file.name;
    const fileExt = fileName.split('.').pop().toLowerCase();
    
    if (fileExt !== 'py' && fileExt !== 'txt') {
        showToast('Please upload a Python (.py) or text (.txt) file', 'error');
        fileInput.value = '';
        return;
    }
    
    // Check file size (max 5MB)
    const maxSize = 5 * 1024 * 1024; // 5MB
    if (file.size > maxSize) {
        showToast('File too large. Maximum size is 5MB', 'error');
        fileInput.value = '';
        return;
    }
    
    // Read file content
    const reader = new FileReader();
    
    reader.onload = function(e) {
        const content = e.target.result;
        codeEditor.value = content;
        updateCodeStats();
        fileInfoText.innerHTML = `<i class="fas fa-file-code"></i> ${fileName}`;
        showToast(`File "${fileName}" loaded successfully`, 'success');
        fileInput.value = ''; // Reset input
    };
    
    reader.onerror = function() {
        showToast('Error reading file', 'error');
        fileInput.value = '';
    };
    
    reader.readAsText(file);
}

// Load example code
function loadExample() {
    codeEditor.value = EXAMPLE_CODE;
    updateCodeStats();
    fileInfoText.textContent = 'Example vulnerable code';
    showToast('Example code loaded', 'success');
}

// Clear all
function clearAll() {
    codeEditor.value = '';
    fileInfoText.textContent = 'No file loaded';
    fileInput.value = '';
    updateCodeStats();
    resetResults();
    showToast('Cleared', 'success');
}

// Reset results
function resetResults() {
    statusValue.textContent = 'N/A';
    statusValue.className = 'status-value';
    confidenceValue.textContent = 'N/A';
    priorityValue.textContent = 'N/A';
    timeValue.textContent = 'N/A';
    
    loadingState.style.display = 'none';
    resultsContainer.style.display = 'none';
    emptyState.style.display = 'block';
}

// Analyze code
async function analyzeCode() {
    const code = codeEditor.value.trim();
    
    if (!code) {
        showToast('Please enter code to analyze', 'warning');
        return;
    }
    
    // Show loading state
    loadingState.style.display = 'flex';
    emptyState.style.display = 'none';
    resultsContainer.style.display = 'none';
    analyzeBtn.disabled = true;
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ code: code })
        });
        
        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Analysis failed');
        }
        
        // Hide loading, show results
        loadingState.style.display = 'none';
        
        // Check if valid Python
        if (!data.is_valid_python) {
            displaySyntaxError(data);
        } else {
            displayResults(data);
        }
        
        showToast('Analysis complete', 'success');
        
    } catch (error) {
        loadingState.style.display = 'none';
        emptyState.style.display = 'block';
        showToast(`Error: ${error.message}`, 'error');
    } finally {
        analyzeBtn.disabled = false;
    }
}

// Display syntax error
function displaySyntaxError(data) {
    statusValue.textContent = 'N/A';
    confidenceValue.textContent = 'N/A';
    priorityValue.textContent = 'N/A';
    timeValue.textContent = `${data.analysis_time.toFixed(2)}s`;
    
    resultsContainer.style.display = 'block';
    resultsContainer.innerHTML = `
        <div class="result-section fade-in">
            <div class="section-header" style="color: ${getComputedStyle(document.documentElement).getPropertyValue('--warning')};">
                <i class="fas fa-exclamation-triangle"></i>
                Invalid Python Code
            </div>
            <div class="section-body">
                <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                    The provided code contains syntax errors and cannot be analyzed.
                </p>
                <div class="stat-item">
                    <span class="stat-label">Error:</span>
                    <span class="stat-value" style="color: var(--danger);">${escapeHtml(data.syntax_error)}</span>
                </div>
                <p style="margin-top: 1rem; color: var(--text-secondary);">
                    Please provide valid Python code to perform security analysis.
                </p>
            </div>
        </div>
    `;
}

// Display analysis results
function displayResults(data) {
    // Update status cards
    const isVulnerable = data.is_vulnerable;
    const confidence = data.confidence;
    const urgency = data.urgency_score;
    
    statusValue.textContent = isVulnerable ? 'VULNERABLE' : 'SAFE';
    statusValue.className = isVulnerable ? 'status-value vulnerable' : 'status-value safe';
    
    confidenceValue.textContent = `${confidence.toFixed(1)}%`;
    
    let priority = 'LOW';
    if (isVulnerable) {
        if (urgency > 80) priority = 'CRITICAL';
        else if (urgency > 60) priority = 'HIGH';
        else if (urgency > 40) priority = 'MEDIUM';
    }
    priorityValue.textContent = priority;
    priorityValue.className = isVulnerable ? 'status-value vulnerable' : 'status-value safe';
    
    timeValue.textContent = `${data.analysis_time.toFixed(2)}s`;
    
    // Build results HTML
    let resultsHTML = '';
    
    // Code Statistics
    resultsHTML += buildStatisticsSection(data.statistics);
    
    // Vulnerabilities
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        resultsHTML += buildVulnerabilitiesSection(data.vulnerabilities);
    } else if (isVulnerable) {
        resultsHTML += `
            <div class="result-section fade-in">
                <div class="section-header" style="color: var(--warning);">
                    <i class="fas fa-exclamation-triangle"></i>
                    Security Assessment
                </div>
                <div class="section-body">
                    <div class="stat-item">
                        <span class="stat-label">Status:</span>
                        <span class="stat-value">Potentially vulnerable</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">ML Confidence:</span>
                        <span class="stat-value">${confidence.toFixed(1)}%</span>
                    </div>
                    <p style="margin-top: 1rem; color: var(--text-secondary);">
                        The ML model flagged this code as potentially risky. Manual code review is recommended.
                    </p>
                </div>
            </div>
        `;
    } else {
        resultsHTML += `
            <div class="result-section fade-in">
                <div class="section-header" style="color: var(--success);">
                    <i class="fas fa-check-circle"></i>
                    Security Assessment
                </div>
                <div class="section-body">
                    <p style="color: var(--success); font-weight: 600; margin-bottom: 0.5rem;">
                        No vulnerabilities detected
                    </p>
                    <p style="color: var(--text-secondary);">
                        Code appears secure based on pattern matching, AST analysis, and ML detection.
                    </p>
                </div>
            </div>
        `;
    }
    
    // Risk Factors
    if (data.risk_factors) {
        resultsHTML += buildRiskFactorsSection(data.risk_factors);
    }
    
    // Recommendations
    if (data.recommendations && data.recommendations.length > 0) {
        resultsHTML += buildRecommendationsSection(data.recommendations, isVulnerable);
    }
    
    // Display results
    resultsContainer.innerHTML = resultsHTML;
    resultsContainer.style.display = 'block';
}

// Build statistics section
function buildStatisticsSection(stats) {
    return `
        <div class="result-section fade-in">
            <div class="section-header">
                <i class="fas fa-chart-bar"></i>
                Code Statistics
            </div>
            <div class="section-body">
                <div class="stat-grid">
                    <div class="stat-item">
                        <span class="stat-label">Code Length:</span>
                        <span class="stat-value">${stats.code_length.toLocaleString()} chars</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Lines of Code:</span>
                        <span class="stat-value">${stats.line_count.toLocaleString()}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">SQL Keywords:</span>
                        <span class="stat-value">${stats.sql_keywords}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Dangerous Functions:</span>
                        <span class="stat-value">${stats.dangerous_functions}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">String Operations:</span>
                        <span class="stat-value">${stats.string_operations}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Network Operations:</span>
                        <span class="stat-value">${stats.network_operations}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">File Operations:</span>
                        <span class="stat-value">${stats.file_operations}</span>
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Build vulnerabilities section
function buildVulnerabilitiesSection(vulnerabilities) {
    let html = `
        <div class="result-section fade-in">
            <div class="section-header" style="color: var(--severity-critical);">
                <i class="fas fa-bug"></i>
                Vulnerabilities Detected (${vulnerabilities.length})
            </div>
            <div class="section-body">
    `;
    
    vulnerabilities.forEach((vuln, index) => {
        const severity = vuln.severity.toLowerCase();
        const icon = {
            'critical': 'fas fa-times-circle',
            'high': 'fas fa-exclamation-circle',
            'medium': 'fas fa-exclamation-triangle',
            'low': 'fas fa-info-circle'
        }[severity] || 'fas fa-exclamation-triangle';
        
        html += `
            <div class="vulnerability-card ${severity}">
                <div class="vuln-header ${severity}">
                    <div class="vuln-title">
                        <i class="${icon}"></i>
                        <span>#${index + 1} ${escapeHtml(vuln.type)}</span>
                    </div>
                    <span>${vuln.severity}</span>
                </div>
                <div class="vuln-body">
                    <div class="vuln-description">
                        ${escapeHtml(vuln.description)}
                    </div>
                    <div class="vuln-meta">
                        <span><i class="fas fa-shield-alt"></i> Severity: ${vuln.severity}</span>
                        <span><i class="fas fa-map-marker-alt"></i> Line: ${vuln.line}</span>
                        <span><i class="fas fa-search"></i> Detection: ${vuln.detection}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    html += `
            </div>
        </div>
    `;
    
    return html;
}

// Build risk factors section
function buildRiskFactorsSection(riskFactors) {
    return `
        <div class="result-section fade-in">
            <div class="section-header">
                <i class="fas fa-shield-alt"></i>
                Risk Assessment
            </div>
            <div class="section-body">
                <div class="risk-grid">
                    ${Object.entries(riskFactors).map(([key, value]) => `
                        <div class="risk-item">
                            <span class="stat-label">${formatRiskLabel(key)}:</span>
                            <span class="risk-badge ${value.toLowerCase()}">${value}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

// Build recommendations section
function buildRecommendationsSection(recommendations, isVulnerable) {
    const headerColor = isVulnerable ? 'var(--severity-critical)' : 'var(--success)';
    const headerIcon = isVulnerable ? 'fas fa-lightbulb' : 'fas fa-check-circle';
    const headerText = isVulnerable ? 'Recommendations' : 'Security Best Practices';
    
    let html = `
        <div class="result-section fade-in">
            <div class="section-header" style="color: ${headerColor};">
                <i class="${headerIcon}"></i>
                ${headerText}
            </div>
            <div class="section-body">
    `;
    
    recommendations.forEach(rec => {
        if (rec.category) {
            html += `<div class="recommendation-category">${escapeHtml(rec.category)}</div>`;
        }
        html += `<ul class="recommendation-list">`;
        rec.items.forEach(item => {
            html += `<li>${escapeHtml(item)}</li>`;
        });
        html += `</ul>`;
    });
    
    html += `
            </div>
        </div>
    `;
    
    return html;
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatRiskLabel(key) {
    return key.split('_').map(word => 
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

function showToast(message, type = 'success') {
    toast.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}
