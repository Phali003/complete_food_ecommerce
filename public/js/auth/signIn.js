/**
 * signIn.js - Handles user authentication and login form logic
 */

// Declare openModal in global scope so it can be accessed outside the module
window.openModal = null;

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const loginBtn = document.getElementById('loginBtn');
    const authModal = document.getElementById('authModal');
    const modalBackdrop = document.getElementById('modalBackdrop');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const passwordToggles = document.querySelectorAll('.password-toggle');
    
    // Form elements
    const signinForm = document.getElementById('signinForm');
    const signinEmail = document.getElementById('signinEmail');
    const signinPassword = document.getElementById('signinPassword');
    const signinButton = document.getElementById('signinButton');
    const rememberMeCheckbox = document.getElementById('rememberMe');
    const signinAlert = document.getElementById('signinAlert');
    const signinEmailError = document.getElementById('signinEmailError');
    const signinPasswordError = document.getElementById('signinPasswordError');
    
    // Forgot password form elements
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    const resetEmail = document.getElementById('resetEmail');  // Changed variable name to match HTML
    const resetPasswordButton = document.getElementById('resetPasswordButton');
    const forgotPasswordAlert = document.getElementById('forgotPasswordAlert');
    const forgotPasswordSuccessAlert = document.getElementById('forgotPasswordSuccessAlert');
    const forgotPasswordEmailError = document.getElementById('resetEmailError');
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    const switchToSignup = document.getElementById('switchToSignup');
    const switchToSigninFromForgot = document.getElementById('switchToSigninFromForgot');
    
    // API endpoint constants
    const API_BASE_URL = '/api/auth';
    const LOGIN_ENDPOINT = `${API_BASE_URL}/login`;
    const LOGOUT_ENDPOINT = `${API_BASE_URL}/logout`;

    // Open modal when login button is clicked
    if (loginBtn) {
        loginBtn.addEventListener('click', function(e) {
            e.preventDefault();
            openModal();
        });
    }

    // Close modal when close button is clicked
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', () => {
            closeModal();
        });
    }

    // Close modal when clicking outside of it
    if (modalBackdrop) {
        modalBackdrop.addEventListener('click', (e) => {
            if (e.target === modalBackdrop) {
                closeModal();
            }
        });
    }

    // Handle tab switching
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabName = button.getAttribute('data-tab');
            showTab(tabName);
        });
    });

    // Enhanced password toggle functionality
    function handlePasswordToggle(e) {
        e.preventDefault();
        e.stopPropagation();
        
        const toggle = e.currentTarget;
        const targetId = toggle.getAttribute('data-target');
        // Toggle password visibility
        
        const passwordInput = document.getElementById(targetId);
        if (!passwordInput) {
            return;
        }
        
        // Toggle password visibility
        passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
        
        // Toggle icon
        const icon = toggle.querySelector('i');
        if (icon) {
            if (passwordInput.type === 'text') {
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        }
    }
    
    function setupPasswordToggles() {
        // Set up password visibility toggles
        
        // Get all password toggle buttons
        const passwordToggles = document.querySelectorAll('.password-toggle');
        
        passwordToggles.forEach(toggle => {
            const targetId = toggle.getAttribute('data-target');
            
            const passwordInput = document.getElementById(targetId);
            
            // First, remove any existing onclick property
            toggle.onclick = null;
            
            // Then remove event listeners (needs to be a named function to remove)
            toggle.removeEventListener('click', handlePasswordToggle);
            
            // Add new click handler
            toggle.addEventListener('click', handlePasswordToggle);
            // Initialize toggle functionality
        });
    }
    
    // Call the setup function initially
    setupPasswordToggles();
    
    // Also set up password toggles when tabs are switched
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Wait for the tab to be shown before setting up toggles
            setTimeout(setupPasswordToggles, 100);
        });
    });

    // Direct tab navigation links
    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', () => {
            showTab('forgot-password');
        });
    }

    if (switchToSignup) {
        switchToSignup.addEventListener('click', (e) => {
            e.preventDefault();
            showTab('signup');
        });
    }

    if (switchToSigninFromForgot) {
        switchToSigninFromForgot.addEventListener('click', (e) => {
            e.preventDefault();
            showTab('signin');
        });
    }

    // Form validation and submission
    if (signinForm) {
        signinForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            // Clear previous errors
            clearErrorStates();
            
            // Validate form
            let isValid = validateSignInForm();
            
            if (isValid) {
                attemptLogin();
            }
        });
    }

    // Input validation on blur events
    if (signinEmail) {
        signinEmail.addEventListener('blur', () => {
            validateSignInEmail();
        });
    }

    if (signinPassword) {
        signinPassword.addEventListener('blur', () => {
            validateSignInPassword();
        });
    }

    // Forgot password email validation on blur
    if (resetEmail) {
        resetEmail.addEventListener('blur', () => {
            validateForgotPasswordEmail();
        });
    }

    // Simple setup for forgot password functionality
    if (forgotPasswordForm && resetPasswordButton) {
        // Initialize password reset functionality
        
        // Add form submit handler
        forgotPasswordForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            // Clear any previous error messages
            clearForgotPasswordErrors();
            
            // Validate the email and proceed if valid
            if (validateForgotPasswordEmail()) {
                // Process validated reset request
                handleForgotPassword();
            } else {
                // Validation failed - no further action
            }
        });
        
        // Make sure button is type="submit" (matching HTML)
        resetPasswordButton.setAttribute('type', 'submit');
        
        // Forgot password handler set up successfully
    } else {
        // Form elements not available
    }

    /**
     * Opens the authentication modal and sets default active tab
     */
    function openModal() {
        authModal.classList.add('active');
        modalBackdrop.classList.add('active');
        document.documentElement.classList.add('modal-open');
        // Set focus to the first input field in the active tab
        setTimeout(() => {
            const activeTab = document.querySelector('.tab-pane.active');
            const firstInput = activeTab.querySelector('input');
            if (firstInput) firstInput.focus();
        }, 300);
    }
    
    // Expose the openModal function to the global scope
    window.openModal = openModal;

    /**
     * Closes the authentication modal
     */
    function closeModal() {
        // Before closing, ensure any visible alerts are properly cleaned up
        const visibleAlerts = document.querySelectorAll('.alert.visible');
        visibleAlerts.forEach(alert => {
            // Force immediate cleanup of any visible alerts
            alert.classList.remove('visible', 'alert-error', 'alert-success');
            alert.style.opacity = '';
            alert.style.transition = '';
            alert.textContent = '';
            
            // Also clean up their timeouts
            cleanupElementTimeouts(alert);
        });
        
        authModal.classList.remove('active');
        modalBackdrop.classList.remove('active');
        document.documentElement.classList.remove('modal-open');
        cleanupAlertTimeouts();
        clearAllAlerts();
        signinForm.reset();
    }

    function showTab(tabName) {
        // Store currently active tab
        const previousTab = document.querySelector('.tab-pane.active');
        const newTab = document.getElementById(tabName);
        
        if (!newTab) return;
        
        // First, handle any visible alerts in the current tab
        if (previousTab) {
            const visibleAlerts = previousTab.querySelectorAll('.alert.visible');
            visibleAlerts.forEach(alert => {
                // For error alerts, hide immediately without transition
                if (alert.classList.contains('alert-error')) {
                    alert.style.transition = 'none';
                    alert.classList.remove('visible');
                    alert.offsetHeight; // Force reflow
                } 
                // For all alerts including success, clean up properly
                else {
                    alert.style.transition = 'none';
                    alert.classList.remove('visible', 'alert-success', 'alert-error');
                    alert.style.opacity = '';
                    alert.style.transition = '';
                    alert.textContent = '';
                    alert.offsetHeight; // Force reflow
                }
            });
            
            // Clean up any existing alert timeouts when switching tabs
            cleanupAlertTimeouts();
        }
        
        // Hide all tabs and remove active class from buttons
        tabPanes.forEach(pane => {
            pane.classList.remove('active');
        });
        tabButtons.forEach(btn => btn.classList.remove('active'));
        
        // Get the new tab button
        const newTabBtn = document.querySelector(`.tab-btn[data-tab="${tabName}"]`);
        
        // Clear only error states, preserve success states
        clearErrorStates();
        
        // Also clear forgot password error states
        if (forgotPasswordAlert && forgotPasswordEmailError) {
            clearForgotPasswordErrorStates();
        }
        
        // Small delay to ensure alert transitions complete
        setTimeout(() => {
            // Restore transitions
            document.querySelectorAll('.alert').forEach(alert => {
                alert.style.transition = '';
            });
            
            // Show new tab and set active class on button
            newTab.classList.add('active');
            if (newTabBtn) newTabBtn.classList.add('active');
            
            // Focus on first input after transition
            setTimeout(() => {
                const firstInput = newTab.querySelector('input');
                if (firstInput) firstInput.focus();
            }, 300); // Match the CSS transition duration
        }, 50); // Small delay for transition coordination
    }
    /**
     * Clears only error states in the sign-in form, preserving success alerts
     */
    function clearErrorStates() {
        // Get currently active tab
        const activeTab = document.querySelector('.tab-pane.active');
        if (!activeTab) return;
        
        // First, set transition to none on all alerts to prevent flash
        const alerts = activeTab.querySelectorAll('.alert');
        alerts.forEach(alert => {
            alert.style.transition = 'none';
            alert.offsetHeight; // Force reflow
        });
        
        // Clear error classes from inputs
        signinEmail.classList.remove('error');
        signinPassword.classList.remove('error');
        
        // Clear individual field error messages
        signinEmailError.classList.remove('visible');
        signinEmailError.textContent = '';
        signinPasswordError.classList.remove('visible');
        signinPasswordError.textContent = '';
        
        // Only clear the sign-in alert if it's showing an error
        if (signinAlert.classList.contains('alert-error')) {
            signinAlert.classList.remove('visible', 'alert-error');
            signinAlert.textContent = '';
        }
        
        // Restore transitions after a brief delay
        setTimeout(() => {
            alerts.forEach(alert => {
                alert.style.transition = '';
            });
        }, 50);
    }
    function clearAllAlerts() {
        // Clear all alert states
        signinAlert.classList.remove('visible', 'alert-error', 'alert-success');
        signinAlert.textContent = '';
        signinAlert.style.opacity = '';
        signinAlert.style.transition = '';
        
        // Clear error states
        signinEmail.classList.remove('error');
        signinPassword.classList.remove('error');
        signinEmailError.classList.remove('visible');
        signinEmailError.textContent = '';
        signinPasswordError.classList.remove('visible');
        signinPasswordError.textContent = '';
        
        // Also clear forgot password alerts if they exist
        if (forgotPasswordAlert) {
            forgotPasswordAlert.classList.remove('visible', 'alert-error', 'alert-success');
            forgotPasswordAlert.textContent = '';
            forgotPasswordAlert.style.opacity = '';
            forgotPasswordAlert.style.transition = '';
        }
        
        if (forgotPasswordSuccessAlert) {
            forgotPasswordSuccessAlert.classList.remove('visible', 'alert-success');
            forgotPasswordSuccessAlert.textContent = '';
            forgotPasswordSuccessAlert.style.opacity = '';
            forgotPasswordSuccessAlert.style.transition = '';
        }
    }
    
    /**
     * Cleans up any existing alert timeouts to prevent overlapping behavior
     */
    function cleanupAlertTimeouts() {
        // Use the unified cleanup function for each alert element
        cleanupElementTimeouts(signinAlert);
        
        // Clean up forgot password alerts
        if (forgotPasswordAlert) {
            cleanupElementTimeouts(forgotPasswordAlert);
            
            // Cleanup legacy timeout identifiers
            if (forgotPasswordAlert.dataset.errorTimeoutId) {
                clearTimeout(parseInt(forgotPasswordAlert.dataset.errorTimeoutId, 10));
                delete forgotPasswordAlert.dataset.errorTimeoutId;
            }
        }
        
        // Clean up forgot password success alerts
        if (forgotPasswordSuccessAlert) {
            cleanupElementTimeouts(forgotPasswordSuccessAlert);
        }
    }

    /**
     * Clears only error states in the forgot password form, preserving success alerts
     */
    function clearForgotPasswordErrorStates() {
        if (forgotPasswordAlert && forgotPasswordAlert.classList.contains('alert-error')) {
            // First set transition to none to prevent visibility transition from showing
            forgotPasswordAlert.style.transition = 'none';
            forgotPasswordAlert.offsetHeight; // Force reflow
            
            // Remove visible class
            forgotPasswordAlert.classList.remove('visible', 'alert-error');
            forgotPasswordAlert.textContent = '';
            
            // After a short delay, reset the transition property
            setTimeout(() => {
                forgotPasswordAlert.style.transition = '';
            }, 50);
        }
        
        if (forgotPasswordEmailError) {
            forgotPasswordEmailError.classList.remove('visible');
            forgotPasswordEmailError.textContent = '';
            resetEmail.classList.remove('error');
        }
    }
    function clearForgotPasswordErrors() {
        if (forgotPasswordAlert) {
            // Clear any existing timeouts
            if (forgotPasswordAlert.dataset.errorTimeoutId) {
                clearTimeout(parseInt(forgotPasswordAlert.dataset.errorTimeoutId, 10));
                delete forgotPasswordAlert.dataset.errorTimeoutId;
            }
            
            if (forgotPasswordAlert.dataset.fadeOutTimeoutId) {
                clearTimeout(parseInt(forgotPasswordAlert.dataset.fadeOutTimeoutId, 10));
                delete forgotPasswordAlert.dataset.fadeOutTimeoutId;
            }
            
            // Remove error classes immediately without animation for clean state
            forgotPasswordAlert.style.transition = 'none';
            forgotPasswordAlert.classList.remove('visible', 'alert-error', 'alert-success');
            forgotPasswordAlert.innerHTML = '';
            forgotPasswordAlert.removeAttribute('data-error-code');
            forgotPasswordAlert.removeAttribute('role');
            forgotPasswordAlert.removeAttribute('aria-live');
            forgotPasswordAlert.style.opacity = '';
            
            // Restore transition after brief delay
            setTimeout(() => {
                forgotPasswordAlert.style.transition = '';
            }, 50);
        }
        
        if (forgotPasswordEmailError) {
            forgotPasswordEmailError.classList.remove('visible');
            forgotPasswordEmailError.textContent = '';
            resetEmail.classList.remove('error');
        }
    }
    /**
     * Validates the entire sign-in form
     * @returns {boolean} True if the form is valid, false otherwise
     */
    function validateSignInForm() {
        // First clear all previous errors
        clearErrorStates();
        
        // Then validate each field
        let isEmailValid = validateSignInEmail();
        let isPasswordValid = validateSignInPassword();
        
        // Add shake animation if validation fails
        if (!(isEmailValid && isPasswordValid)) {
            signinForm.classList.add('shake');
            setTimeout(() => {
                signinForm.classList.remove('shake');
            }, 500);
        }
        
        return isEmailValid && isPasswordValid;
    }

    /**
     * Validates the email/username field
     * @returns {boolean} True if valid, false otherwise
     */
    function validateSignInEmail() {
        if (!signinEmail.value.trim()) {
            signinEmailError.textContent = 'Email or username is required';
            signinEmailError.classList.add('visible');
            signinEmail.classList.add('error');
            return false;
        }
        
        signinEmailError.classList.remove('visible');
        signinEmail.classList.remove('error');
        return true;
    }

    /**
     * Validates the password field
     * @returns {boolean} True if valid, false otherwise
     */
    function validateSignInPassword() {
        if (!signinPassword.value) {
            signinPasswordError.textContent = 'Password is required';
            signinPasswordError.classList.add('visible');
            signinPassword.classList.add('error');
            return false;
        }
        
        signinPasswordError.classList.remove('visible');
        signinPassword.classList.remove('error');
        return true;
    }

    /**
     * Validates the email in the forgot password form
     * @returns {boolean} True if valid, false otherwise
     */
    function validateForgotPasswordEmail() {
        // Using the globally declared elements instead of re-querying
        if (!resetEmail) {
            return false;
        }
        
        const resetEmailError = document.getElementById('resetEmailError');
        if (!resetEmailError) {
            return false;
        }
        
        const email = resetEmail.value.trim();
        
        if (!email) {
            resetEmailError.textContent = 'Email is required';
            resetEmailError.classList.add('visible');
            resetEmail.classList.add('error');
            return false;
        }
        
        // Check email format using regex
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            resetEmailError.textContent = 'Please enter a valid email address';
            resetEmailError.classList.add('visible');
            resetEmail.classList.add('error');
            return false;
        }
        
        resetEmailError.classList.remove('visible');
        resetEmail.classList.remove('error');
        return true;
    }

    /**
     * Attempts to log in the user with the provided credentials
     */
    function attemptLogin() {
        // Clear any previous errors
        clearErrorStates();
        
        // Show loading state
        signinButton.classList.add('btn-loading');
        signinButton.disabled = true;
        
        const emailOrUsername = signinEmail.value.trim();
        const password = signinPassword.value;
        
        // Create request payload using the expected "identifier" field format
        const loginData = {
            identifier: emailOrUsername,
            password: password
        };
        
        // Send authentication request to server
        
        // Make API request to login
        fetch(LOGIN_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(loginData),
            credentials: 'same-origin' // Send cookies with the request
        })
        .then(response => {
            // Check if the response is JSON
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return response.json().then(data => {
                    // Return both the response status and data together
                    return { status: response.status, data };
                });
            } else {
                // If not JSON, return text
                return response.text().then(text => {
                    return { status: response.status, data: { message: text } };
                });
            }
        })
        .then(result => {
            const { status, data } = result;
            
            // Handle server response
            
            // Handle response based on status code
            if (status >= 200 && status < 300 && data.success) {
                // Successful login
                // Check different response structures that might exist
                let userData = null;
                let token = null;
                
                if (data.data && data.data.user) {
                    // Structure: { success: true, data: { user: {...}, token: "..." } }
                    userData = data.data.user;
                    token = data.data.token;
                } else if (data.user) {
                    // Structure: { success: true, user: {...}, token: "..." }
                    userData = data.user;
                    token = data.token;
                }
                
                if (userData && token) {
                    handleSuccessfulLogin(userData, token);
                } else {
                    // Invalid response format
                    handleFailedLogin('Login successful but response format invalid');
                }
            } else {
                // Failed login
                handleFailedLogin(data.message || 'Invalid email/username or password');
            }
        })
        .catch(error => {
            // Handle connection errors
            handleFailedLogin('Network error. Please try again later.');
        })
        .finally(() => {
            // Remove loading state
            signinButton.classList.remove('btn-loading');
            signinButton.disabled = false;
        });
    }

/**
 * Shows an alert message with auto-dismissal functionality
 * @param {HTMLElement} element - The alert element to show
 * @param {string} message - The message to display
 * @param {string} type - The type of alert ('success' or 'error')
 * @param {number} duration - Display duration in milliseconds before fading out
 * @returns {void}
 */
function showAlert(element, message, type, duration = 3500) {
    if (!element) return;
    
    // First clean up any existing timeouts
    cleanupElementTimeouts(element);
    
    // Prepare the alert - first remove transition to avoid flicker
    element.style.transition = 'none';
    element.classList.remove('visible', 'alert-success', 'alert-error');
    element.textContent = message;
    element.offsetHeight; // Force reflow
    
    // Add the appropriate classes
    element.classList.add(type === 'success' ? 'alert-success' : 'alert-error');
    
    // Small delay before showing to ensure proper transition
    setTimeout(() => {
        // Restore transition and show alert
        element.style.transition = '';
        element.style.opacity = '1';
        element.classList.add('visible');
        
        // Auto-dismiss after specified duration
        const alertTimeout = setTimeout(() => {
            // Add a fade-out transition
            element.style.transition = 'opacity 0.4s ease-out';
            element.style.opacity = '0';
            
            // After the transition completes, clean up
            const fadeOutTimeout = setTimeout(() => {
                // Additional check to ensure the element still exists in the DOM
                if (element && document.body.contains(element)) {
                    // Always clean up alert regardless of type
                    element.classList.remove('visible', 'alert-error', 'alert-success');
                    element.style.opacity = '';
                    element.style.transition = '';
                    element.textContent = '';
                }
            }, 400); // Match transition duration
            
            // Store the fade-out timeout ID
            element.dataset.fadeOutTimeoutId = fadeOutTimeout;
        }, duration);
        
        // Store the alert timeout ID
        element.dataset.alertTimeoutId = alertTimeout;
    }, 10);
}

/**
 * Cleans up timeouts for a specific element
 * @param {HTMLElement} element - The element with timeouts to clean up
 */
function cleanupElementTimeouts(element) {
    if (!element) return;
    
    // Clear alert timeout
    if (element.dataset.alertTimeoutId) {
        clearTimeout(parseInt(element.dataset.alertTimeoutId, 10));
        delete element.dataset.alertTimeoutId;
    }
    
    // Clear fade-out timeout
    if (element.dataset.fadeOutTimeoutId) {
        clearTimeout(parseInt(element.dataset.fadeOutTimeoutId, 10));
        delete element.dataset.fadeOutTimeoutId;
    }
    
    // Always reset styles and classes for all alerts when cleaning up
    element.classList.remove('visible', 'alert-error', 'alert-success');
    element.style.opacity = '';
    element.style.transition = '';
    element.textContent = '';
}

/**
 * Handles a successful login attempt
 * @param {Object} user - The authenticated user object
 * @param {string} token - The authentication token from the server
 */
function handleSuccessfulLogin(user, token) {
    // Save session information if "Remember me" is checked
    const userData = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        token: token,
        isLoggedIn: true,
        loginTime: new Date().toISOString()
    };
    
    if (rememberMeCheckbox.checked) {
        localStorage.setItem('currentUser', JSON.stringify(userData));
    } else {
        // Use sessionStorage for session-only login state
        sessionStorage.setItem('currentUser', JSON.stringify(userData));
    }
    
    // Use 3.5 seconds (3500ms) for consistent timing with other alerts
    const alertDuration = 3500;
    
    // Show success message using the unified function with 3.5 second duration
    showAlert(signinAlert, `Welcome back, ${user.username}!`, 'success', alertDuration);
        
    // Close modal and refresh page after the alert duration (3.5 seconds)
    setTimeout(() => {
        closeModal();
        updateUIForLoggedInUser(user);
    }, alertDuration);
}

    /**
     * Handles a failed login attempt
     * @param {string} errorMessage - Optional custom error message
     */
    function handleFailedLogin(errorMessage = 'Invalid email/username or password') {
        // Clear any existing alerts before showing error
        clearAllAlerts();
        
        // Show error message using the unified function
        showAlert(signinAlert, errorMessage, 'error');
        
        // Shake the form to indicate error
        signinForm.classList.add('shake');
        setTimeout(() => {
            signinForm.classList.remove('shake');
        }, 500);
    }

    /**
     * Updates the UI to reflect logged-in state
     * @param {Object} user - The authenticated user object
     */
    function updateUIForLoggedInUser(user) {
        // Change login button to show username
        if (loginBtn) {
            loginBtn.innerHTML = `<i class="fas fa-user"></i> ${user.username}`;
            
            // Change event listener to show user options instead of login modal
            loginBtn.removeEventListener('click', openModal);
            loginBtn.addEventListener('click', showUserOptions);
        }
    }

    /**
    /**
     * Shows user options dropdown (placeholder function)
     */
    function showUserOptions() {
        // This would typically show a dropdown with options like "Profile", "Orders", "Logout", etc.
        // For now, let's implement a simple logout functionality
        if (confirm('Do you want to log out?')) {
            // Get current user data to get token
            const currentUser = JSON.parse(localStorage.getItem('currentUser')) || 
                              JSON.parse(sessionStorage.getItem('currentUser'));
            
            // Call logout API if we have token
            if (currentUser && currentUser.token) {
                fetch(LOGOUT_ENDPOINT, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${currentUser.token}`,
                        'Content-Type': 'application/json'
                    },
                    credentials: 'same-origin'
                })
                .then(response => {
                    // Process logout response
                })
                .catch(error => {
                    // Process logout error
                })
                .finally(() => {
                    // Clear storage and reload regardless of API response
                    localStorage.removeItem('currentUser');
                    sessionStorage.removeItem('currentUser');
                    location.reload();
                });
            } else {
                // If no token found, just clear storage and reload
                localStorage.removeItem('currentUser');
                sessionStorage.removeItem('currentUser');
                location.reload();
            }
        }
    }
    /**
     * Checks if user is already logged in and updates UI accordingly
     */
    function checkLoggedInStatus() {
        const currentUser = JSON.parse(localStorage.getItem('currentUser')) || 
                          JSON.parse(sessionStorage.getItem('currentUser'));
        
        if (currentUser && currentUser.isLoggedIn) {
            updateUIForLoggedInUser(currentUser);
        }
    }
    // Check if user is already logged in when page loads
    checkLoggedInStatus();
    
    /**
     * Handles the forgot password request with rate limiting protection
     */
    function handleForgotPassword() {
        // Process password reset request
        
        // Check rate limiting before proceeding
        if (!checkResetRateLimit(resetEmail.value.trim())) {
            return;
        }
        
        resetPasswordButton.classList.add('btn-loading');
        resetPasswordButton.disabled = true;
        
        clearForgotPasswordErrors();
        
        if (!resetEmail) {
            return;
        }
        
        const email = resetEmail.value.trim();
        
        // Track this reset attempt
        trackResetAttempt(email);
        
        fetch('/api/auth/forgot-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email })
        })
        .then(async response => {
            const data = await response.json();
            
            resetPasswordButton.classList.remove('btn-loading');
            resetPasswordButton.disabled = false;
        
            if (response.ok && data.success) {
                // Clean up any existing timeouts for success alert specifically
                cleanupElementTimeouts(forgotPasswordSuccessAlert);
                
                // Show success message with auto-dismiss after 3.5 seconds
                showAlert(forgotPasswordSuccessAlert, 'Password reset instructions have been sent to your email.', 'success', 3500);
                forgotPasswordForm.reset();
                
                // Wait slightly longer than the alert duration to switch tabs
                // This ensures the fade-out animation completes before tab switch
                setTimeout(() => {
                    // Clean up the alert completely before switching tabs
                    if (forgotPasswordSuccessAlert) {
                        cleanupElementTimeouts(forgotPasswordSuccessAlert);
                    }
                    
                    // Switch to sign-in tab
                    showTab('signin');
                }, 3900); // 3.5s alert duration + 0.4s fade-out transition
            } else if (response.status === 404) {
                // Clean up any existing timeouts for error alert specifically
                cleanupElementTimeouts(forgotPasswordAlert);
                
                // Show error message using the unified function
                showAlert(forgotPasswordAlert, data.message || 'No account found with this email address.', 'error');
            } else {
                throw new Error(data.message || `Server error: ${response.status}`);
            }
        })
        .catch(error => {
            // Create a safe wrapper for the error object to avoid circular references
            let safeError;
            
            try {
                // First try to safely convert the error to a serializable format
                // This handles potential circular references or complex object structures
                const getCircularReplacer = () => {
                    const seen = new WeakSet();
                    return (key, value) => {
                        // Skip functions and DOM nodes which can't be meaningfully serialized
                        if (typeof value === 'function' || 
                            (value && typeof value === 'object' && value.nodeType)) {
                            return '[Function/DOM]';
                        }
                        // Handle circular references
                        if (typeof value === 'object' && value !== null) {
                            if (seen.has(value)) {
                                return '[Circular]';
                            }
                            seen.add(value);
                        }
                        return value;
                    };
                };
                
                // Try to extract essential error info safely
                safeError = JSON.parse(JSON.stringify(error, getCircularReplacer()));
            } catch (serializationError) {
                // If serialization fails, create a basic error object with essential properties
                safeError = {};
            }
            
            // Structure error for logging with safe handling of nested objects
            const sanitizedError = {
                name: error.name || safeError.name || 'UnknownError',
                message: error.message || safeError.message || 'No error message available',
                stack: error.stack || safeError.stack || 'No stack trace available',
                // Extract response details if available, with failsafes
                response: error.response ? {
                    status: error.response.status,
                    statusText: error.response.statusText,
                    body: error.response.body || null
                } : null,
                // Include any available API error info
                apiError: error.apiError || safeError.apiError || null,
                // Include any original error if this is a wrapper
                originalError: error.originalError ? {
                    name: error.originalError.name,
                    message: error.originalError.message,
                    stack: error.originalError.stack
                } : null,
                // Track whether this was a connection, server or client error
                errorType: error.name === 'TypeError' ? 'connection' : 
                           (error.response && error.response.status >= 500) ? 'server' : 
                           (error.response && error.response.status >= 400) ? 'client' : 'unknown'
            };
            
            // Process password reset error
            
            // Reset UI state
            resetPasswordButton.classList.remove('btn-loading');
            resetPasswordButton.disabled = false;
            
            // Create error object with code, message, and help text
            let errorData = {
                code: 'ERR_UNKNOWN',
                message: 'An error occurred while processing your request. Please try again later.',
                helpText: 'If this problem persists, please contact customer support.'
            };
            
            // More specific error checking with enhanced messages
            
            // Check for network related errors
            if (error.name === 'TypeError' && error.message.includes('fetch')) {
                errorData = {
                    code: 'ERR_NETWORK',
                    message: 'Network error: Please check your internet connection and try again.',
                    helpText: 'Make sure you have a stable internet connection.'
                };
            }
            // Check for specific server response status codes
            else if (error.response) {
                if (error.response.status === 429) {
                    errorData = {
                        code: 'ERR_RATE_LIMIT_SERVER',
                        message: 'Too many requests. Please try again later.',
                        helpText: 'The server has received too many requests. Please wait a few minutes before trying again.'
                    };
                } else if (error.response.status === 404) {
                    errorData = {
                        code: 'ERR_EMAIL_NOT_FOUND',
                        message: 'The email address was not found in our system.',
                        helpText: 'Please check your email address or create a new account.'
                    };
                } else if (error.response.status >= 500) {
                    errorData = {
                        code: 'ERR_SERVER',
                        message: 'Server error. We apologize for the inconvenience.',
                        helpText: 'Our team has been notified of this issue. Please try again later.'
                    };
                }
            }
            // Check for specific error messages from the server
            else if (error.message.includes('password reset request')) {
                errorData = {
                    code: 'ERR_RESET_SERVICE',
                    message: 'The password reset service is currently unavailable.',
                    helpText: 'Please try again later or contact support for assistance.'
                };
            }
            // Check specifically for the error reported in the issue
            else if (error.message.includes('Error processing password reset request')) {
                errorData = {
                    code: 'ERR_RESET_PROCESSING',
                    message: 'We encountered an issue processing your password reset request.',
                    helpText: 'This is a temporary issue. Please try again in a few minutes.'
                };
            }
            // Handle timeout errors
            else if (error.name === 'TimeoutError' || error.message.includes('timeout')) {
                errorData = {
                    code: 'ERR_TIMEOUT',
                    message: 'The request timed out.',
                    helpText: 'The server is taking too long to respond. Please try again when the server is less busy.'
                };
            }
            // Handle specific API error messages if they've been passed through
            else if (error.apiError) {
                errorData = {
                    code: 'ERR_API_SPECIFIC',
                    message: error.apiError,
                    helpText: 'Please check the error message for specific instructions.'
                };
            }
            // Handle rate limiting errors
            else if (error.rateLimitExceeded) {
                errorData = {
                    code: 'ERR_RATE_LIMIT',
                    message: 'Too many password reset attempts.',
                    helpText: 'Please wait before trying again to ensure account security.'
                };
            }
            // Handle invalid email format errors
            else if (error.message.includes('email') && error.message.includes('format')) {
                errorData = {
                    code: 'ERR_INVALID_EMAIL',
                    message: 'The email format is invalid.',
                    helpText: 'Please enter a valid email address in the format user@example.com.'
                };
            }
            
            // Create a more structured error message display
            forgotPasswordAlert.innerHTML = ''; // Clear any existing content
            
            // Create error code element
            const errorCodeEl = document.createElement('span');
            errorCodeEl.className = 'error-code';
            errorCodeEl.textContent = `[${errorData.code}]`;
            
            // Create error message element
            const errorMessageEl = document.createElement('span');
            errorMessageEl.className = 'error-message';
            errorMessageEl.textContent = ` ${errorData.message}`;
            
            // Create help text element if available
            if (errorData.helpText) {
                const helpTextEl = document.createElement('div');
                helpTextEl.className = 'error-help-text';
                helpTextEl.textContent = errorData.helpText;
                forgotPasswordAlert.appendChild(helpTextEl);
            }
            
            // Create dismiss button
            const dismissBtn = document.createElement('button');
            dismissBtn.textContent = '×';
            dismissBtn.className = 'dismiss-error-btn';
            dismissBtn.setAttribute('aria-label', 'Dismiss error message');
            dismissBtn.addEventListener('click', (e) => {
                e.preventDefault();
                clearForgotPasswordErrors();
            });
            
            // Assemble the error alert
            forgotPasswordAlert.appendChild(errorCodeEl);
            forgotPasswordAlert.appendChild(errorMessageEl);
            forgotPasswordAlert.appendChild(dismissBtn);
            
            // Set data attributes for tracking and styling
            forgotPasswordAlert.setAttribute('data-error-code', errorData.code);
            forgotPasswordAlert.classList.add('visible', 'alert-error');
            
            // Add accessibility attributes
            forgotPasswordAlert.setAttribute('role', 'alert');
            forgotPasswordAlert.setAttribute('aria-live', 'assertive');
            
            // Track this error for analytics (could be implemented to send to server)
            trackError(errorData.code, errorData.message, sanitizedError);
            
            // Setup event listeners for interactive error cleanup
            resetEmail.addEventListener('focus', clearForgotPasswordErrors, { once: true });
            
            // Add more interactive error cleanup - clear on input with debounce
            let inputDebounceTimer;
            resetEmail.addEventListener('input', () => {
                clearTimeout(inputDebounceTimer);
                inputDebounceTimer = setTimeout(() => {
                    if (forgotPasswordAlert.classList.contains('visible')) {
                        fadeOutError(forgotPasswordAlert);
                    }
                }, 500); // Wait for 500ms of inactivity before hiding error
            });
            
            // Add escape key listener to dismiss error
            const escKeyHandler = (e) => {
                if (e.key === 'Escape' && forgotPasswordAlert.classList.contains('visible')) {
                    fadeOutError(forgotPasswordAlert);
                    document.removeEventListener('keydown', escKeyHandler);
                }
            };
            document.addEventListener('keydown', escKeyHandler);
            
            // Set a longer timeout for more complex error messages
            const displayTime = errorData.helpText ? 10000 : 6000; // Give users more time to read
            
            
            
            // For severe errors, also log to server
            if (['ERR_SERVER', 'ERR_RESET_PROCESSING', 'ERR_UNKNOWN'].includes(errorData.code)) {
                // This would be implemented to send error logs to server
                // Process severe error
                
                // Create a safe error object for server logging
                const loggableError = {
                    code: errorData.code,
                    message: errorData.message,
                    timestamp: new Date().toISOString(),
                    userAgent: navigator.userAgent,
                    errorDetails: {
                        type: sanitizedError.name,
                        text: sanitizedError.message,
                        errorType: sanitizedError.errorType
                    }
                };
                
                // Log to server would be implemented here
                // Example: logErrorToServer(loggableError);
            }
            
            // Add a data-error-source attribute to help with debugging
            forgotPasswordAlert.setAttribute('data-error-source', 'password-reset');
        });
    }

    /**
     * Checks if the user has exceeded the rate limit for password reset attempts
     * @param {string} email - The email address being used for reset
     * @returns {boolean} - True if within rate limit, false if exceeded
     */
    function checkResetRateLimit(email) {
        const MAX_ATTEMPTS = 3;             // Maximum attempts allowed
        const LIMIT_WINDOW_MS = 15 * 60000; // 15 minutes in milliseconds
        
        // Get reset attempts from localStorage
        const resetAttemptsData = JSON.parse(localStorage.getItem('passwordResetAttempts')) || {};
        const userAttempts = resetAttemptsData[email] || [];
        
        // Filter attempts to only include those within the time window
        const now = Date.now();
        const recentAttempts = userAttempts.filter(timestamp => (now - timestamp) < LIMIT_WINDOW_MS);
        
        // Check if user has exceeded the rate limit
        if (recentAttempts.length >= MAX_ATTEMPTS) {
            // Process rate limiting
            
            // Calculate time until next allowed attempt
            const oldestAttempt = Math.min(...recentAttempts);
            const msUntilReset = LIMIT_WINDOW_MS - (now - oldestAttempt);
            const minutesUntilReset = Math.ceil(msUntilReset / 60000);
            
            // Show rate limit error
            resetPasswordButton.classList.remove('btn-loading');
            resetPasswordButton.disabled = false;
            
            forgotPasswordAlert.textContent = `[ERR_RATE_LIMIT] Too many reset attempts. Please try again in ${minutesUntilReset} minutes.`;
            forgotPasswordAlert.classList.add('visible', 'alert-error');
            
            // Add a clear button to the error message
            const clearButton = document.createElement('button');
            clearButton.textContent = 'Dismiss';
            clearButton.className = 'dismiss-error-btn';
            clearButton.addEventListener('click', (e) => {
                e.preventDefault();
                forgotPasswordAlert.classList.remove('visible');
            });
            
            // Append the button if it doesn't already exist
            if (!forgotPasswordAlert.querySelector('.dismiss-error-btn')) {
                forgotPasswordAlert.appendChild(clearButton);
            }
            
            return false; // Rate limit exceeded
        }
        
        return true; // Within rate limit
    }
    
    /**
     * Tracks a password reset attempt for rate limiting purposes
     * @param {string} email - The email address being used for reset
     */
    function trackResetAttempt(email) {
        // Get existing attempts data
        const resetAttemptsData = JSON.parse(localStorage.getItem('passwordResetAttempts')) || {};
        
        // Add this attempt
        if (!resetAttemptsData[email]) {
            resetAttemptsData[email] = [];
        }
        
        resetAttemptsData[email].push(Date.now());
        
        // Clean up old attempts (older than 1 hour)
        const ONE_HOUR_MS = 60 * 60 * 1000;
        const now = Date.now();
        
        Object.keys(resetAttemptsData).forEach(userEmail => {
            resetAttemptsData[userEmail] = resetAttemptsData[userEmail].filter(
                timestamp => (now - timestamp) < ONE_HOUR_MS
            );
            
            // Remove email entry if no recent attempts
            if (resetAttemptsData[userEmail].length === 0) {
                delete resetAttemptsData[userEmail];
            }
        });
        
        // Save updated attempts data
        localStorage.setItem('passwordResetAttempts', JSON.stringify(resetAttemptsData));
    }

    /**
     * Tracks errors for analytics purposes
     * @param {string} code - Error code
     * @param {string} message - Error message
     * @param {Object} errorDetails - Full error details for logging
     */
    function trackError(code, message, errorDetails) {
        try {
            // Error tracking for monitoring
            
            // Create a sanitized version for potential analytics
            const trackingData = {
                code: code,
                message: message,
                timestamp: Date.now(),
                page: window.location.pathname,
                errorType: errorDetails.errorType || 'unknown',
                // Include minimal details that won't cause issues
                details: {
                    name: errorDetails.name,
                    shortMessage: errorDetails.message?.substring(0, 100) // Truncate for safety
                }
            };
            
            // Store recent errors in session storage for debugging
            const recentErrors = JSON.parse(sessionStorage.getItem('recentErrors') || '[]');
            recentErrors.unshift(trackingData);
            
            // Keep only the last 5 errors
            if (recentErrors.length > 5) {
                recentErrors.pop();
            }
            
            sessionStorage.setItem('recentErrors', JSON.stringify(recentErrors));
            
            // In a production environment, this could send error data to an analytics service
            // Example: sendToAnalytics(trackingData);
        } catch (e) {
            // Ensure tracking never breaks the app
            // Error tracking process failed
        }
    }
    
    /**
     * Fades out an error message with smooth transition
     * @param {HTMLElement} errorElement - The error element to fade out
     */
    function fadeOutError(errorElement) {
        if (!errorElement) return;
        
        // Add a fade-out transition to smoothly hide the element
        errorElement.style.transition = 'opacity 0.5s ease-out';
        errorElement.style.opacity = '0';
        
        // Clear any existing timeout
        if (errorElement.dataset.errorTimeoutId) {
            clearTimeout(parseInt(errorElement.dataset.errorTimeoutId, 10));
            delete errorElement.dataset.errorTimeoutId;
        }
        
        // After the transition completes, remove the visible class and reset opacity
        const transitionTimeout = setTimeout(() => {
            errorElement.classList.remove('visible', 'alert-error');
            errorElement.style.opacity = '';
            errorElement.style.transition = '';
            
            // Clear the content after the fade is complete
            setTimeout(() => {
                // Only clear if there wasn't a new error added while fading
                if (!errorElement.classList.contains('visible')) {
                    errorElement.innerHTML = '';
                    errorElement.removeAttribute('data-error-code');
                    errorElement.removeAttribute('role');
                    errorElement.removeAttribute('aria-live');
                }
            }, 100);
        }, 500); // Match the transition duration
        
        return transitionTimeout;
    }

    /**
     * Generates a secure random token for password reset
     * @returns {string} A random token
     */
    function generateResetToken() {
        // In a real application, use a more secure method to generate tokens
        const tokenLength = 32;
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let token = '';
        
        for (let i = 0; i < tokenLength; i++) {
            token += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        return token;
    }
    
    /**
     * Stores the reset token in localStorage with expiration time
     * @param {string} email - The user's email
     * @param {string} token - The generated reset token
     */
    function storeResetToken(email, token) {
        // Get existing tokens or initialize empty object
        const resetTokens = JSON.parse(localStorage.getItem('resetTokens')) || {};
        
        // Set expiration time (15 minutes from now)
        const expirationTime = new Date();
        expirationTime.setMinutes(expirationTime.getMinutes() + 15);
        
        // Store token with email and expiration
        resetTokens[token] = {
            email: email,
            expires: expirationTime.toISOString()
        };
        
        // Save back to localStorage
        localStorage.setItem('resetTokens', JSON.stringify(resetTokens));
    }
});

// Add a direct event listener on the login button in global scope for redundancy
document.addEventListener('DOMContentLoaded', function() {
    const loginBtn = document.getElementById('loginBtn');
    if (loginBtn) {
        loginBtn.addEventListener('click', function(e) {
            e.preventDefault();
            if (typeof window.openModal === 'function') {
                window.openModal();
            } else {
                // Modal function not available
                // Fallback implementation if openModal is not available
                const authModal = document.getElementById('authModal');
                const modalBackdrop = document.getElementById('modalBackdrop');
                if (authModal && modalBackdrop) {
                    authModal.classList.add('active');
                    modalBackdrop.classList.add('active');
                    document.documentElement.classList.add('modal-open');
                }
            }
        });
    }
});
