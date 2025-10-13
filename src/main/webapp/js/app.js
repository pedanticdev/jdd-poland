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
        document.querySelectorAll('.test-user-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.getElementById('username').value = btn.dataset.username;
                document.getElementById('password').value = btn.dataset.password;
                handleLogin(new Event('submit'));
            });
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
        userInfo.textContent = `Welcome, ${user.preferred_username} (${user.roles.join(', ')})`;
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
            const errorData = await response.json().catch(() => ({ message: 'An unknown error occurred' }));
            throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
        }
        return response.json();
    }

    /**
     * Data Loading
     */
    async function loadDashboardData() {
        loadPatients();
        loadSecurityEvents();
        loadSecurityConfig();
    }

    async function loadPatients() {
        try {
            patientsContainer.innerHTML = '<div class="loading">Loading patients...</div>';
            const patients = await apiFetch(`${API_BASE_URL}/patients`);
            renderPatients(patients);
        } catch (error) {
            // Non-admin users will get a 403, which is expected.
            if (user.roles.includes('ADMIN')) {
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