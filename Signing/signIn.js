/**
 * signIn.js - Handles user authentication and login form logic
 */

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
    const forgotPasswordEmail = document.getElementById('resetEmail');  // Updated to match HTML
    const forgotPasswordButton = document.getElementById('resetPasswordButton');  // Updated to match HTML
    const forgotPasswordAlert = document.getElementById('forgotPasswordAlert');
    const forgotPasswordEmailError = document.getElementById('resetEmailError');  // Updated to match HTML
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    const switchToSignup = document.getElementById('switchToSignup');
    const switchToSigninFromForgot = document.getElementById('switchToSigninFromForgot');
    
    // API endpoint constants
    const API_BASE_URL = '/api/auth';
    const LOGIN_ENDPOINT = `${API_BASE_URL}/login`;
    const LOGOUT_ENDPOINT = `${API_BASE_URL}/logout`;

    // Open modal when login button is clicked
    if (loginBtn) {
        loginBtn.addEventListener('click', () => {
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
        console.log('Toggle clicked for:', targetId);
        
        const passwordInput = document.getElementById(targetId);
        if (!passwordInput) {
            console.error('Password input not found:', targetId);
            return;
        }
        
        // Toggle password visibility
        passwordInput.type = passwordInput.type === 'password' ? 'text' : 'password';
        console.log('Changed input type to:', passwordInput.type);
        
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
        console.log('Setting up password toggles');
        
        // Get all password toggle buttons and log their data-target attributes
        const passwordToggles = document.querySelectorAll('.password-toggle');
        console.log('Found password toggles:', passwordToggles.length);
        
        passwordToggles.forEach(toggle => {
            const targetId = toggle.getAttribute('data-target');
            console.log('Found toggle with target:', targetId);
            
            const passwordInput = document.getElementById(targetId);
            console.log('Found password input for ' + targetId + ':', passwordInput ? 'yes' : 'no');
            
            // First, remove any existing onclick property
            toggle.onclick = null;
            
            // Then remove event listeners (needs to be a named function to remove)
            toggle.removeEventListener('click', handlePasswordToggle);
            
            // Add new click handler
            toggle.addEventListener('click', handlePasswordToggle);
            console.log('Added click handler for toggle:', targetId);
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
    if (forgotPasswordEmail) {
        forgotPasswordEmail.addEventListener('blur', () => {
            validateForgotPasswordEmail();
        });
    }

    // Simple setup for forgot password functionality
    if (forgotPasswordForm && forgotPasswordButton) {
        console.log('Setting up forgot password button handler');
        
        // Remove form's submit handler completely
        forgotPasswordForm.addEventListener('submit', (e) => {
            e.preventDefault();
            return false;
        });
        
        // Set button type to "button"
        forgotPasswordButton.setAttribute('type', 'button');
        
        // Add click handler using addEventListener
        forgotPasswordButton.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log('Reset password button clicked');
            
            // Clear any previous error messages
            clearForgotPasswordErrors();
            
            // Validate the email and proceed if valid
            if (validateForgotPasswordEmail()) {
                console.log('Email validation passed - processing reset');
                handleForgotPassword();
            } else {
                console.log('Email validation failed - not proceeding');
            }
        });
        
        console.log('Forgot password handler set up successfully');
    } else {
        console.error('Could not find forgot password form or button');
    }

    /**
     * Opens the authentication modal and sets default active tab
     */
    function openModal() {
        authModal.classList.add('active');
        modalBackdrop.classList.add('active');
        document.documentElement.classList.add('modal-open');
        console.log('Opening modal - added active class');
        // Set focus to the first input field in the active tab
        setTimeout(() => {
            const activeTab = document.querySelector('.tab-pane.active');
            const firstInput = activeTab.querySelector('input');
            if (firstInput) firstInput.focus();
        }, 300);
    }

    /**
     * Closes the authentication modal
     */
    function closeModal() {
        authModal.classList.remove('active');
        modalBackdrop.classList.remove('active');
        document.documentElement.classList.remove('modal-open');
        console.log('Closing modal - removed active class');
        clearAllAlerts();
        signinForm.reset();
    }

    function showTab(tabName) {
        // Store currently active tab
        const previousTab = document.querySelector('.tab-pane.active');
        const newTab = document.getElementById(tabName);
        
        if (!newTab) return;
        
        // First, hide any visible alerts in the current tab without transition
        if (previousTab) {
            const visibleAlerts = previousTab.querySelectorAll('.alert.visible');
            visibleAlerts.forEach(alert => {
                // Only hide error alerts, preserve success alerts
                if (alert.classList.contains('alert-error')) {
                    alert.style.transition = 'none';
                    alert.classList.remove('visible');
                    alert.offsetHeight; // Force reflow
                }
            });
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
        
        // Clear error states
        signinEmail.classList.remove('error');
        signinPassword.classList.remove('error');
        signinEmailError.classList.remove('visible');
        signinEmailError.textContent = '';
        signinPasswordError.classList.remove('visible');
        signinPasswordError.textContent = '';
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
            forgotPasswordEmail.classList.remove('error');
        }
    }
    function clearForgotPasswordErrors() {
        if (forgotPasswordAlert) {
            forgotPasswordAlert.classList.remove('visible', 'alert-error', 'alert-success');
            forgotPasswordAlert.textContent = '';
        }
        
        if (forgotPasswordEmailError) {
            forgotPasswordEmailError.classList.remove('visible');
            forgotPasswordEmailError.textContent = '';
            forgotPasswordEmail.classList.remove('error');
        }
    }
    /**
     * Validates the entire sign-in form
     * @returns {boolean} True if the form is valid, false otherwise
     */
    function validateSignInForm() {
        let isEmailValid = validateSignInEmail();
        let isPasswordValid = validateSignInPassword();
        
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
        if (!forgotPasswordEmail) {
            console.error('Forgot password email element not found');
            return false;
        }
        
        if (!forgotPasswordEmailError) {
            console.error('Forgot password email error element not found');
            return false;
        }
        
        const email = forgotPasswordEmail.value.trim();
        console.log('Validating email:', email); // Debug log
        
        if (!email) {
            forgotPasswordEmailError.textContent = 'Email is required';
            forgotPasswordEmailError.classList.add('visible');
            forgotPasswordEmail.classList.add('error');
            return false;
        }
        
        // Check email format using regex
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            forgotPasswordEmailError.textContent = 'Please enter a valid email address';
            forgotPasswordEmailError.classList.add('visible');
            forgotPasswordEmail.classList.add('error');
            return false;
        }
        
        forgotPasswordEmailError.classList.remove('visible');
        forgotPasswordEmail.classList.remove('error');
        return true;
    }

    /**
     * Attempts to log in the user with the provided credentials
     */
    function attemptLogin() {
        // Show loading state
        signinButton.classList.add('btn-loading');
        signinButton.disabled = true;
        
        const emailOrUsername = signinEmail.value.trim();
        const password = signinPassword.value;
        
        // Determine if input is email or username based on format
        const isEmail = emailOrUsername.includes('@');
        
        // Create request payload
        const loginData = {
            password: password
        };
        
        // Add either email or username field depending on what was entered
        if (isEmail) {
            loginData.email = emailOrUsername;
        } else {
            loginData.username = emailOrUsername;
        }
        
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
            
            // Add debug logging
            console.log('Login response:', { status, data });
            
            // Handle response based on status code
            if (status >= 200 && status < 300 && data.success) {
                // Successful login - note that user and token are directly in data object
                handleSuccessfulLogin(data.user, data.token);
            } else {
                // Failed login
                handleFailedLogin(data.message || 'Invalid email/username or password');
            }
        })
        .catch(error => {
            console.error('Login error:', error);
            handleFailedLogin('Network error. Please try again later.');
        })
        .finally(() => {
            // Remove loading state
            signinButton.classList.remove('btn-loading');
            signinButton.disabled = false;
        });
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
        
        // Show success message
        signinAlert.textContent = `Welcome back, ${user.username}!`;
        signinAlert.classList.remove('alert-error');
        signinAlert.classList.add('alert-success', 'visible');
        
        // Close modal and refresh page after a short delay
        setTimeout(() => {
            closeModal();
            updateUIForLoggedInUser(user);
        }, 1500);
    }

    /**
     * Handles a failed login attempt
     * @param {string} errorMessage - Optional custom error message
     */
    function handleFailedLogin(errorMessage = 'Invalid email/username or password') {
        // Clear any existing alerts before showing error
        clearAllAlerts();
        
        // First set transition to none and hide alert
        signinAlert.style.transition = 'none';
        signinAlert.classList.remove('visible', 'alert-error', 'alert-success');
        signinAlert.textContent = '';
        signinAlert.offsetHeight; // Force reflow
        
        // Prepare the alert with error message and classes
        signinAlert.textContent = errorMessage;
        signinAlert.classList.add('alert-error');
        
        // Small delay before showing the alert to ensure proper transition
        setTimeout(() => {
            // Restore transition and show alert
            signinAlert.style.transition = '';
            signinAlert.classList.add('visible');
            
            // Shake the form to indicate error
            signinForm.classList.add('shake');
            setTimeout(() => {
                signinForm.classList.remove('shake');
            }, 500);

            // Hide the error message after 3 seconds
            setTimeout(() => {
                signinAlert.style.transition = 'opacity 0.3s ease-out';
                signinAlert.classList.remove('visible');
                // Clear the message after fade out
                setTimeout(() => {
                    signinAlert.textContent = '';
                    signinAlert.classList.remove('alert-error');
                }, 300);
            }, 3000);
        }, 10);
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
                    console.log('Logout response:', response.status);
                })
                .catch(error => {
                    console.error('Logout error:', error);
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
     * Handles the forgot password request
     */
    function handleForgotPassword() {
        console.log('Handling forgot password request - processing email: ' + forgotPasswordEmail.value); // Debug log
        
        // Get the button directly to avoid any reference issues
        const resetBtn = document.getElementById('resetPasswordButton');
        
        // Apply loading state to button
        if (resetBtn) {
            resetBtn.classList.add('btn-loading');
            resetBtn.disabled = true;
        }
        
        // Simulate network request delay
        setTimeout(() => {
            const email = forgotPasswordEmail.value.trim();
            
            // Retrieve users from localStorage
            const users = JSON.parse(localStorage.getItem('users')) || [];
            
            // Check if email exists in user database
            const userExists = users.some(user => user.email === email);
            
            if (userExists) {
                // Generate a reset token
                const resetToken = generateResetToken();
                
                // Store token in localStorage
                storeResetToken(email, resetToken);
                
                // Create reset link (for demonstration)
                const resetLink = `${window.location.origin}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;
                
                // Log reset link to console (in a real app, this would be sent via email)
                console.log('Password Reset Link:', resetLink);
                alert('For demonstration purposes, the reset link has been logged to the console.');
                
                // Show success message
                forgotPasswordAlert.textContent = 'Password reset link has been sent to your email';
                forgotPasswordAlert.classList.remove('alert-error');
                forgotPasswordAlert.classList.add('alert-success', 'visible');
                
                // Clear the form after successful submission
                forgotPasswordForm.reset();
            } else {
                // Email not found
                forgotPasswordAlert.textContent = 'Email not found in our records';
                forgotPasswordAlert.classList.remove('alert-success');
                forgotPasswordAlert.classList.add('alert-error', 'visible');
            }
            
            // Get the button directly and remove loading state
            const resetBtn = document.getElementById('resetPasswordButton');
            if (resetBtn) {
                resetBtn.classList.remove('btn-loading');
                resetBtn.disabled = false;
            }
        }, 1000);
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


