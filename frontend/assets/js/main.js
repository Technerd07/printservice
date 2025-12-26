// DOM Elements
const navbar = document.getElementById('navbar');
const navLinks = document.getElementById('navLinks');
const mobileMenuBtn = document.getElementById('mobileMenuBtn');
const loginSection = document.getElementById('login');
const loginTab = document.getElementById('loginTab');
const registerTab = document.getElementById('registerTab');
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const forgotForm = document.getElementById('forgotForm');
const loginMessage = document.getElementById('loginMessage');
const registerMessage = document.getElementById('registerMessage');
const forgotMessage = document.getElementById('forgotMessage');
const passwordMatchMessage = document.getElementById('passwordMatchMessage');

// Password visibility toggles
const loginPassword = document.getElementById('loginPassword');
const loginPasswordToggle = loginPassword.nextElementSibling;
const registerPassword = document.getElementById('registerPassword');
const registerPasswordToggle = registerPassword.nextElementSibling;
const registerPasswordConfirm = document.getElementById('registerPasswordConfirm');
const registerPasswordConfirmToggle = registerPasswordConfirm.nextElementSibling;

// Password strength meter
const registerPasswordStrength = document.querySelector('.password-strength');
const strengthBar = document.querySelector('.strength-bar');
const strengthText = document.querySelector('.strength-text span');

// Form validation
const API_BASE_URL = 'http://localhost:8080/api';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    setupPasswordStrength();
    checkAuthStatus();
});

// Setup all event listeners
function setupEventListeners() {
    // Mobile menu toggle
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', toggleMobileMenu);
    }

    // Tab switching
    if (loginTab) {
        loginTab.addEventListener('click', () => switchTab('login'));
    }

    if (registerTab) {
        registerTab.addEventListener('click', () => switchTab('register'));
    }

    // Password visibility toggles
    if (loginPasswordToggle) {
        loginPasswordToggle.addEventListener('click', () => togglePasswordVisibility(loginPassword, loginPasswordToggle));
    }

    if (registerPasswordToggle) {
        registerPasswordToggle.addEventListener('click', () => togglePasswordVisibility(registerPassword, registerPasswordToggle));
    }

    if (registerPasswordConfirmToggle) {
        registerPasswordConfirmToggle.addEventListener('click', () => togglePasswordVisibility(registerPasswordConfirm, registerPasswordConfirmToggle));
    }

    // Form submissions
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }

    if (forgotForm) {
        forgotForm.addEventListener('submit', handleForgotPassword);
    }

    // Password confirmation check
    if (registerPasswordConfirm) {
        registerPasswordConfirm.addEventListener('input', checkPasswordMatch);
    }

    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = anchor.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Navbar scroll effect
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
}

// Toggle mobile menu
function toggleMobileMenu() {
    navLinks.classList.toggle('active');
}

// Switch between login and register tabs
function switchTab(tab) {
    // Hide all forms
    loginForm.classList.remove('active');
    registerForm.classList.remove('active');
    forgotForm.classList.remove('active');
    
    // Remove active class from all tabs
    loginTab.classList.remove('active');
    registerTab.classList.remove('active');
    
    // Show selected form and activate tab
    if (tab === 'login') {
        loginForm.classList.add('active');
        loginTab.classList.add('active');
    } else if (tab === 'register') {
        registerForm.classList.add('active');
        registerTab.classList.add('active');
    }
    
    // Clear any messages
    hideAllMessages();
}

// Toggle password visibility
function togglePasswordVisibility(input, toggleBtn) {
    if (input.type === 'password') {
        input.type = 'text';
        toggleBtn.textContent = '👁️';
    } else {
        input.type = 'password';
        toggleBtn.textContent = '👁️';
    }
}

// Setup password strength meter
function setupPasswordStrength() {
    if (!registerPassword || !strengthBar || !strengthText) return;
    
    registerPassword.addEventListener('input', () => {
        const password = registerPassword.value;
        const strength = calculatePasswordStrength(password);
        
        // Update strength bar
        strengthBar.style.width = `${strength.percentage}%`;
        strengthBar.style.backgroundColor = strength.color;
        
        // Update strength text
        strengthText.textContent = strength.label;
        
        // Update parent class for styling
        registerPasswordStrength.className = `password-strength ${strength.class}`;
    });
}

// Calculate password strength
function calculatePasswordStrength(password) {
    if (!password) return { percentage: 0, color: '#ef4444', class: 'password-weak', label: 'Weak' };
    
    let score = 0;
    
    // Length check
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    
    // Complexity checks
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^a-zA-Z0-9]/.test(password)) score += 1;
    
    // Return strength object
    if (score <= 2) {
        return { percentage: 25, color: '#ef4444', class: 'password-weak', label: 'Weak' };
    } else if (score <= 3) {
        return { percentage: 50, color: '#f59e0b', class: 'password-fair', label: 'Fair' };
    } else if (score <= 4) {
        return { percentage: 75, color: '#3b82f6', class: 'password-good', label: 'Good' };
    } else {
        return { percentage: 100, color: '#10b981', class: 'password-strong', label: 'Strong' };
    }
}

// Check if passwords match
function checkPasswordMatch() {
    const password = registerPassword.value;
    const confirmPassword = registerPasswordConfirm.value;
    
    if (!confirmPassword) {
        passwordMatchMessage.textContent = '';
        passwordMatchMessage.classList.remove('show');
        return;
    }
    
    if (password === confirmPassword) {
        passwordMatchMessage.textContent = '✓ Passwords match';
        passwordMatchMessage.classList.add('success');
        passwordMatchMessage.classList.remove('error');
    } else {
        passwordMatchMessage.textContent = '✗ Passwords do not match';
        passwordMatchMessage.classList.add('error');
        passwordMatchMessage.classList.remove('success');
    }
}

// Hide all messages
function hideAllMessages() {
    loginMessage.classList.remove('show', 'error', 'success');
    registerMessage.classList.remove('show', 'error', 'success');
    forgotMessage.classList.remove('show', 'error', 'success');
    passwordMatchMessage.classList.remove('show', 'error', 'success');
}

// Show message
function showMessage(element, message, isError = false) {
    hideAllMessages();
    
    if (message) {
        element.textContent = message;
        element.classList.add('show');
        
        if (isError) {
            element.classList.add('error');
            element.classList.remove('success');
        } else {
            element.classList.add('success');
            element.classList.remove('error');
        }
    }
}

// API call helper
async function apiCall(endpoint, method, data) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json'
        }
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        return await response.json();
    } catch (error) {
        console.error('API call error:', error);
        return { success: false, error: 'Network error. Please try again.' };
    }
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    hideAllMessages();
    
    const identifier = document.getElementById('loginIdentifier').value;
    const password = loginPassword.value;
    
    if (!identifier || !password) {
        showMessage(loginMessage, 'Please enter both email/username and password', true);
        return;
    }
    
    // Show loading state
    const loginBtn = loginForm.querySelector('.login-btn');
    const originalText = loginBtn.textContent;
    loginBtn.textContent = 'Signing in...';
    loginBtn.disabled = true;
    loginBtn.classList.add('loading');
    
    try {
        const data = await apiCall('/auth/login', 'POST', { identifier, password });
        
        if (data.success) {
            // Store token in localStorage
            localStorage.setItem('authToken', data.token);
            
            showMessage(loginMessage, 'Login successful! Redirecting...', false);
            
            // Redirect to dashboard after delay
            setTimeout(() => {
                window.location.href = './dashboard.html';
            }, 1500);
        } else {
            showMessage(loginMessage, data.error || 'Login failed', true);
        }
    } catch (error) {
        showMessage(loginMessage, 'Network error. Please try again.', true);
    } finally {
        // Reset button state
        loginBtn.textContent = originalText;
        loginBtn.disabled = false;
        loginBtn.classList.remove('loading');
    }
}

// Handle registration
async function handleRegister(e) {
    e.preventDefault();
    hideAllMessages();
    
    const username = document.getElementById('registerUsername').value;
    const email = document.getElementById('registerEmail').value;
    const password = registerPassword.value;
    const confirmPassword = registerPasswordConfirm.value;
    const agreeTerms = document.getElementById('agreeTerms').checked;
    
    // Validation
    if (!username || !email || !password || !confirmPassword) {
        showMessage(registerMessage, 'Please fill in all required fields', true);
        return;
    }
    
    if (password !== confirmPassword) {
        showMessage(registerMessage, 'Passwords do not match', true);
        return;
    }
    
    if (!agreeTerms) {
        showMessage(registerMessage, 'Please agree to the Terms of Service and Privacy Policy', true);
        return;
    }
    
    // Show loading state
    const registerBtn = registerForm.querySelector('.register-btn');
    const originalText = registerBtn.textContent;
    registerBtn.textContent = 'Creating account...';
    registerBtn.disabled = true;
    registerBtn.classList.add('loading');
    
    try {
        const data = await apiCall('/auth/register', 'POST', { username, email, password });
        
        if (data.success) {
            showMessage(registerMessage, 'Registration successful! Please check your email to verify your account.', false);
            registerForm.reset();
        } else {
            showMessage(registerMessage, data.error || 'Registration failed', true);
        }
    } catch (error) {
        showMessage(registerMessage, 'Network error. Please try again.', true);
    } finally {
        // Reset button state
        registerBtn.textContent = originalText;
        registerBtn.disabled = false;
        registerBtn.classList.remove('loading');
    }
}

// Handle forgot password
async function handleForgotPassword(e) {
    e.preventDefault();
    hideAllMessages();
    
    const email = document.getElementById('forgotEmail').value;
    
    if (!email) {
        showMessage(forgotMessage, 'Please enter your email address', true);
        return;
    }
    
    // Show loading state
    const forgotBtn = forgotForm.querySelector('.login-btn');
    const originalText = forgotBtn.textContent;
    forgotBtn.textContent = 'Sending...';
    forgotBtn.disabled = true;
    forgotBtn.classList.add('loading');
    
    try {
        const data = await apiCall('/auth/forgot-password', 'POST', { email });
        
        if (data.success) {
            showMessage(forgotMessage, 'Password reset link has been sent to your email', false);
            forgotForm.reset();
        } else {
            showMessage(forgotMessage, data.error || 'Request failed', true);
        }
    } catch (error) {
        showMessage(forgotMessage, 'Network error. Please try again.', true);
    } finally {
        // Reset button state
        forgotBtn.textContent = originalText;
        forgotBtn.disabled = false;
        forgotBtn.classList.remove('loading');
    }
}

// Check authentication status on page load
function checkAuthStatus() {
    const token = localStorage.getItem('authToken');
    
    if (token) {
        // If token exists, redirect to dashboard
        window.location.href = './dashboard.html';
    }
}