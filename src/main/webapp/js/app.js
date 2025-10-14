(function () {
    const API_BASE_URL = '/resources';

    // DOM Elements
    const loginSection = document.getElementById('loginSection');
    const dashboardSection = document.getElementById('dashboardSection');
    const loginForm = document.getElementById('loginForm');
    const loginError = document.getElementById('loginError');
    const userSection = document.getElementById('userSection');
    const userInfo = document.getElementById('userInfo');
    const logoutBtn = document.getElementById('logoutBtn');

    // Dashboard elements
    const statsGrid = document.getElementById('statsGrid');
    const tabs = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const patientsContainer = document.getElementById('patientsContainer');
    const eventsContainer = document.getElementById('eventsContainer');
    const configContainer = document.getElementById('configContainer');
    const refreshMetricsBtn = document.getElementById('refreshMetricsBtn');

    // Modal elements
    const addPatientBtn = document.getElementById('addPatientBtn');
    const addPatientModal = document.getElementById('addPatientModal');
    const addPatientForm = document.getElementById('addPatientForm');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const cancelAddBtn = document.getElementById('cancelAddBtn');
    const addPatientError = document.getElementById('addPatientError');

    // State
    let token = null;
    let user = null;

    /**
     * Initialization
     */
    function init() {
        token = localStorage.getItem('authToken');
        if (token) {
            try {
                user = parseJwt(token);
                showDashboard();
            } catch (e) {
                console.error('Failed to parse token', e);
                logout();
            }
        } else {
            showLogin();
        }

        loginForm.addEventListener('submit', handleLogin);
        logoutBtn.addEventListener('click', logout);
        tabs.forEach(tab => tab.addEventListener('click', handleTabClick));

        // Refresh buttons
        if (refreshMetricsBtn) {
            refreshMetricsBtn.addEventListener('click', loadMetrics);
        }

        // Test user buttons
        document.querySelectorAll('.test-user-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.getElementById('username').value = btn.dataset.username;
                document.getElementById('password').value = btn.dataset.password;
                handleLogin(new Event('submit'));
            });
        });

        // Modal handlers
        addPatientBtn.addEventListener('click', openAddPatientModal);
        closeModalBtn.addEventListener('click', closeAddPatientModal);
        cancelAddBtn.addEventListener('click', closeAddPatientModal);
        addPatientForm.addEventListener('submit', handleAddPatient);

        // Close modal on outside click
        addPatientModal.addEventListener('click', (e) => {
            if (e.target === addPatientModal) {
                closeAddPatientModal();
            }
        });
    }

    /**
     * UI Switching
     */
    function showLogin() {
        loginSection.style.display = 'flex';
        dashboardSection.style.display = 'none';
        userSection.style.display = 'none';
    }

    function showDashboard() {
        loginSection.style.display = 'none';
        dashboardSection.style.display = 'block';
        userSection.style.display = 'flex';
        const roles = user.groups || user.roles || [];
        userInfo.textContent = `Welcome, ${user.preferred_username || user.upn} (${roles.join(', ')})`;
        loadDashboardData();
    }

    function handleTabClick(event) {
        tabs.forEach(tab => tab.classList.remove('active'));
        tabContents.forEach(content => content.classList.remove('active'));

        const tab = event.currentTarget;
        tab.classList.add('active');
        document.getElementById(tab.dataset.tab + 'Tab').classList.add('active');
    }

    /**
     * Authentication
     */
    async function handleLogin(event) {
        event.preventDefault();
        const username = loginForm.username.value;
        const password = loginForm.password.value;

        try {
            const response = await fetch(`${API_BASE_URL}/security/token`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                throw new Error('Invalid username or password');
            }

            const data = await response.json();
            token = data.access_token;
            user = parseJwt(token);
            localStorage.setItem('authToken', token);
            showDashboard();
            loginError.style.display = 'none';
        } catch (error) {
            loginError.textContent = error.message;
            loginError.style.display = 'block';
        }
    }

    function logout() {
        token = null;
        user = null;
        localStorage.removeItem('authToken');
        showLogin();
    }

    /**
     * API Calls
     */
    async function apiFetch(url, options = {}) {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                ...options.headers,
            }
        });

        if (response.status === 401) {
            logout();
            throw new Error('Session expired. Please log in again.');
        }
        if (!response.ok) {
            // Try to parse error response
            let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
            try {
                const errorData = await response.json();
                if (errorData.message) {
                    errorMessage = errorData.message;
                } else if (errorData.error) {
                    errorMessage = errorData.error;
                } else if (errorData.violations && Array.isArray(errorData.violations)) {
                    // Jakarta Bean Validation errors
                    errorMessage = errorData.violations.map(v => `${v.field}: ${v.message}`).join(', ');
                } else if (errorData.parameterViolations && Array.isArray(errorData.parameterViolations)) {
                    // JAX-RS validation errors
                    errorMessage = errorData.parameterViolations.map(v => `${v.path}: ${v.message}`).join(', ');
                }
            } catch (e) {
                // If JSON parsing fails, use the status text
                console.error('Failed to parse error response:', e);
            }
            throw new Error(errorMessage);
        }
        return response.json();
    }

    /**
     * Data Loading
     */
    async function loadDashboardData() {
        loadStats();
        loadPatients();
        loadSecurityEvents();
        loadSecurityConfig();
        loadMetrics();
    }

    async function loadStats() {
        try {
            // Load patient stats
            const patientStats = await apiFetch(`${API_BASE_URL}/patients/stats`);
            document.getElementById('totalPatients').textContent = patientStats.totalPatients || 0;

            // Count unique departments (hardcoded for demo)
            document.getElementById('departmentCount').textContent = '4';

            // Load security metrics for stats
            const securityMetrics = await apiFetch(`${API_BASE_URL}/metrics/security`);
            document.getElementById('authSuccess').textContent = securityMetrics.authenticationSuccess || 0;
            document.getElementById('authFailures').textContent = securityMetrics.authenticationFailure || 0;
        } catch (error) {
            console.error('Error loading stats:', error);
            // Set to 0 if failed to load
            document.getElementById('totalPatients').textContent = '0';
            document.getElementById('departmentCount').textContent = '4';
            document.getElementById('authSuccess').textContent = '0';
            document.getElementById('authFailures').textContent = '0';
        }
    }

    async function loadPatients() {
        try {
            patientsContainer.innerHTML = '<div class="loading">Loading patients...</div>';
            const patients = await apiFetch(`${API_BASE_URL}/patients`);
            renderPatients(patients);
        } catch (error) {
            // Non-admin users will get a 403, which is expected.
            const roles = user.groups || user.roles || [];
            if (roles.includes('ADMIN')) {
                 patientsContainer.innerHTML = `<div class="error-message">${error.message}</div>`;
            } else {
                 patientsContainer.innerHTML = `<div class="info-message">Listing all patients is restricted to administrators. Try the department filter.</div>`;
                 setupDepartmentFilter();
            }
        }
    }
    
    async function setupDepartmentFilter() {
        const departmentFilter = document.getElementById('departmentFilter');
        const departmentSelect = document.getElementById('departmentSelect');
        departmentFilter.style.display = 'block';
        
        // For demo, we assume the user has one department claim
        const userDepartment = user.department;
        if (userDepartment) {
            departmentSelect.innerHTML = `<option value="">Select Department</option><option value="${userDepartment}">${userDepartment}</option>`;
            departmentSelect.value = userDepartment;
            departmentSelect.dispatchEvent(new Event('change'));
        }

        departmentSelect.addEventListener('change', async () => {
            const selectedDept = departmentSelect.value;
            if (selectedDept) {
                try {
                    patientsContainer.innerHTML = '<div class="loading">Loading patients...</div>';
                    const patients = await apiFetch(`${API_BASE_URL}/patients/department/${selectedDept}`);
                    renderPatients(patients);
                } catch (e) {
                    patientsContainer.innerHTML = `<div class="error-message">${e.message}</div>`;
                }
            }
        });
    }

    async function loadSecurityEvents() {
        try {
            eventsContainer.innerHTML = '<div class="loading">Loading security events...</div>';
            const events = await apiFetch(`${API_BASE_URL}/security/events`);
            renderSecurityEvents(events);
        } catch (error) {
            eventsContainer.innerHTML = `<div class="error-message">${error.message}</div>`;
        }
    }

    async function loadSecurityConfig() {
        try {
            configContainer.innerHTML = '<div class="loading">Loading configuration...</div>';
            const config = await apiFetch(`${API_BASE_URL}/security/config`);
            renderSecurityConfig(config);
        } catch (error) {
            configContainer.innerHTML = `<div class="error-message">${error.message}</div>`;
        }
    }

    async function loadMetrics() {
        try {
            // Load security metrics
            const securityMetrics = await apiFetch(`${API_BASE_URL}/metrics/security`);
            renderSecurityMetrics(securityMetrics);

            // Load performance metrics (admin only)
            const roles = user.groups || user.roles || [];
            if (roles.includes('ADMIN')) {
                const performanceMetrics = await apiFetch(`${API_BASE_URL}/metrics/performance`);
                renderPerformanceMetrics(performanceMetrics);
            }
        } catch (error) {
            console.error('Error loading metrics:', error);
        }
    }

    /**
     * Rendering
     */
    function renderPatients(patients) {
        if (!patients || patients.length === 0) {
            patientsContainer.innerHTML = '<p>No patients found.</p>';
            return;
        }
        patientsContainer.innerHTML = patients.map(p => `
            <div class="patient-card">
                <h4>${p.firstName} ${p.lastName}</h4>
                <p><strong>DOB:</strong> ${p.dateOfBirth}</p>
                <p><strong>Department:</strong> ${p.department}</p>
            </div>
        `).join('');
    }

    function renderSecurityEvents(events) {
        if (!events || events.length === 0) {
            eventsContainer.innerHTML = '<p>No security events found.</p>';
            return;
        }
        eventsContainer.innerHTML = events.map(e => `
            <div class="event-item">
                <span class="event-type">${e.type}</span>
                <span class="event-user">${e.username}</span>
                <span class="event-time">${new Date(e.timestamp).toLocaleString()}</span>
                <span class="event-ip">${e.ipAddress}</span>
            </div>
        `).join('');
    }

    function renderSecurityConfig(config) {
        configContainer.innerHTML = `
            <ul>
                <li><strong>Issuer:</strong> ${config.issuer}</li>
                <li><strong>Realm:</strong> ${config.realm}</li>
                <li><strong>Client ID:</strong> ${config.clientId}</li>
                <li><strong>Auth Server:</strong> ${config.authServerUrl}</li>
            </ul>
        `;
    }

    function renderSecurityMetrics(metrics) {
        const metricsGrid = document.querySelector('.metrics-grid');
        metricsGrid.innerHTML = `
            <div class="metric-card">
                <h4>Auth Success</h4>
                <div class="metric-value">${metrics.authenticationSuccess || 0}</div>
                <div class="metric-label">Total successful authentications</div>
            </div>
            <div class="metric-card">
                <h4>Auth Failures</h4>
                <div class="metric-value">${metrics.authenticationFailure || 0}</div>
                <div class="metric-label">Total failed authentication attempts</div>
            </div>
            <div class="metric-card">
                <h4>Authorization Denials</h4>
                <div class="metric-value">${metrics.authorizationFailure || 0}</div>
                <div class="metric-label">Access denied by authorization rules</div>
            </div>
            <div class="metric-card">
                <h4>Suspicious Activity</h4>
                <div class="metric-value">${metrics.suspiciousActivity || 0}</div>
                <div class="metric-label">Detected anomalies and suspicious patterns</div>
            </div>
        `;
    }

    function renderPerformanceMetrics(metrics) {
        const performanceGrid = document.querySelector('.performance-grid');
        const uptimeHours = Math.floor(metrics.uptime / (1000 * 60 * 60));
        const uptimeMinutes = Math.floor((metrics.uptime % (1000 * 60 * 60)) / (1000 * 60));

        performanceGrid.innerHTML = `
            <div class="metric-card">
                <h4>Uptime</h4>
                <div class="metric-value">${uptimeHours}<span class="metric-unit">h</span> ${uptimeMinutes}<span class="metric-unit">m</span></div>
                <div class="metric-label">Application runtime</div>
            </div>
            <div class="metric-card">
                <h4>Heap Usage</h4>
                <div class="metric-value">${metrics.heapUsagePercent ? metrics.heapUsagePercent.toFixed(1) : 0}<span class="metric-unit">%</span></div>
                <div class="metric-label">${metrics.heapUsedMB || 0} MB / ${metrics.heapMaxMB || 0} MB</div>
            </div>
            <div class="metric-card">
                <h4>Processors</h4>
                <div class="metric-value">${metrics.availableProcessors || 0}</div>
                <div class="metric-label">Available CPU cores</div>
            </div>
            <div class="metric-card">
                <h4>System Load</h4>
                <div class="metric-value">${metrics.systemLoadAverage ? metrics.systemLoadAverage.toFixed(2) : 'N/A'}</div>
                <div class="metric-label">Average system load</div>
            </div>
        `;
    }

    /**
     * Modal Functions
     */
    function openAddPatientModal() {
        addPatientModal.style.display = 'block';
        addPatientForm.reset();
        addPatientError.style.display = 'none';
    }

    function closeAddPatientModal() {
        addPatientModal.style.display = 'none';
    }

    async function handleAddPatient(event) {
        event.preventDefault();
        addPatientError.style.display = 'none';

        const formData = new FormData(addPatientForm);

        // Build patient data, only including fields with values
        const patientData = {
            firstName: formData.get('firstName'),
            lastName: formData.get('lastName'),
            dateOfBirth: formData.get('dateOfBirth'),
            department: formData.get('department')
        };

        // Add optional fields only if they have values
        const email = formData.get('email');
        if (email) patientData.email = email;

        const assignedDoctor = formData.get('assignedDoctor');
        if (assignedDoctor) patientData.assignedDoctor = assignedDoctor;

        const phone = formData.get('phone');
        if (phone) patientData.phone = phone;

        const address = formData.get('address');
        if (address) patientData.address = address;

        const bloodType = formData.get('bloodType');
        if (bloodType) patientData.bloodType = bloodType;

        const ssn = formData.get('ssn');
        if (ssn) patientData.ssn = ssn;

        const medicalConditions = formData.get('medicalConditions');
        if (medicalConditions) patientData.medicalConditions = medicalConditions;

        const allergies = formData.get('allergies');
        if (allergies) patientData.allergies = allergies;

        try {
            await apiFetch(`${API_BASE_URL}/patients`, {
                method: 'POST',
                body: JSON.stringify(patientData)
            });

            closeAddPatientModal();
            showToast('Patient added successfully!', 'success');
            loadPatients(); // Reload the patients list
        } catch (error) {
            addPatientError.textContent = error.message;
            addPatientError.style.display = 'block';
        }
    }

    /**
     * Toast Notifications
     */
    function showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('show');
        }, 100);

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    /**
     * Helpers
     */
    function parseJwt(token) {
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (e) {
            return null;
        }
    }

    // Start the app
    init();
})();