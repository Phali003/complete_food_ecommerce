/**
 * signUp.js - Handles user registration with form validation and password strength checking
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const signupForm = document.getElementById('signupForm');
    const signupUsername = document.getElementById('signupUsername');
    const signupEmail = document.getElementById('signupEmail');
    const signupPassword = document.getElementById('signupPassword');
    const confirmPassword = document.getElementById('confirmPassword');
    const signupButton = document.getElementById('signupButton');
    const signupAlert = document.getElementById('signupAlert');
    const signupSuccessAlert = document.getElementById('signupSuccessAlert');
    const usernameError = document.getElementById('usernameError');
    const emailError = document.getElementById('emailError');
    const passwordError = document.getElementById('passwordError');
    const confirmPasswordError = document.getElementById('confirmPasswordError');
    const passwordStrength = document.querySelector('.password-strength');
    const strengthIndicator = document.querySelector('.strength-indicator');
    const strengthText = document.querySelector('.strength-text');
    const switchToSignin = document.getElementById('switchToSignin');

    // Password toggle functionality is already handled in signIn.js

    // Form validation and submission
    if (signupForm) {
        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            // Clear previous errors
            // Clear previous errors
            clearErrorStates();
            
            // Validate form
            let isValid = validateSignupForm();
            if (isValid) {
                registerUser();
            }
        });
    }

    // Tab navigation link
    if (switchToSignin) {
        switchToSignin.addEventListener('click', (e) => {
            e.preventDefault();
            showTab('signin');
        });
    }

    // Input validation on blur and input events
    if (signupUsername) {
        signupUsername.addEventListener('blur', validateUsername);
        signupUsername.addEventListener('input', () => {
            if (signupUsername.classList.contains('error')) {
                validateUsername();
            }
        });
    }

    if (signupEmail) {
        signupEmail.addEventListener('blur', validateEmail);
        signupEmail.addEventListener('input', () => {
            if (signupEmail.classList.contains('error')) {
                validateEmail();
            }
        });
    }

    if (signupPassword) {
        signupPassword.addEventListener('input', () => {
            validatePasswordStrength();
            if (signupPassword.classList.contains('error')) {
                validatePassword();
            }
            // Also validate confirm password if it has a value
            if (confirmPassword.value) {
                validateConfirmPassword();
            }
        });
        
        signupPassword.addEventListener('blur', validatePassword);
    }

    if (confirmPassword) {
        confirmPassword.addEventListener('input', () => {
            if (confirmPassword.classList.contains('error')) {
                validateConfirmPassword();
            }
        });
        
        confirmPassword.addEventListener('blur', validateConfirmPassword);
    }

    /**
     * Clears only error states in the signup form, preserving success alerts
     */
    function clearErrorStates() {
        // Clear individual field error messages
        usernameError.classList.remove('visible');
        usernameError.textContent = '';
        
        emailError.classList.remove('visible');
        emailError.textContent = '';
        
        passwordError.classList.remove('visible');
        passwordError.textContent = '';
        
        confirmPasswordError.classList.remove('visible');
        confirmPasswordError.textContent = '';
        
        // Remove error class from inputs
        signupUsername.classList.remove('error');
        signupEmail.classList.remove('error');
        signupPassword.classList.remove('error');
        confirmPassword.classList.remove('error');
        
        // Only clear the signup alert if it's showing an error
        if (signupAlert.classList.contains('alert-error')) {
            cleanupElementTimeouts(signupAlert);
            signupAlert.classList.remove('visible', 'alert-error');
            signupAlert.textContent = '';
        }
    }
    
    /**
     * Clears all alerts and error states in the signup form
     */
    function clearAllAlerts() {
        // Clear all alert states and their timeouts
        cleanupElementTimeouts(signupAlert);
        cleanupElementTimeouts(signupSuccessAlert);
        
        // Remove classes
        signupAlert.classList.remove('visible', 'alert-error', 'alert-success');
        signupAlert.textContent = '';
        signupSuccessAlert.classList.remove('visible');
        
        // Clear error states
        clearErrorStates();
    }
    
    /**
     * Helper function to show tab (defined in signIn.js but duplicated here for modularity)
     * @param {string} tabName - Name of the tab to show
     */
    function showTab(tabName) {
        const tabPanes = document.querySelectorAll('.tab-pane');
        const tabButtons = document.querySelectorAll('.tab-btn');
        
        // Hide all tabs and remove active class from buttons
        tabPanes.forEach(pane => pane.classList.remove('active'));
        tabButtons.forEach(btn => btn.classList.remove('active'));
        
        // Show selected tab and set active class on button
        document.getElementById(tabName).classList.add('active');
        document.querySelector(`.tab-btn[data-tab="${tabName}"]`).classList.add('active');
        
        // Clear only error states when switching tabs, preserve success states
        clearErrorStates();
        
        // Focus on first input in selected tab (after transition completes)
        setTimeout(() => {
            const firstInput = document.getElementById(tabName).querySelector('input');
            if (firstInput) firstInput.focus();
        }, 300); // Match the CSS transition duration
    }
    
    /**
     * Validates the entire signup form
     * @returns {boolean} True if the form is valid, false otherwise
     */
    function validateSignupForm() {
        let isUsernameValid = validateUsername();
        let isEmailValid = validateEmail();
        let isPasswordValid = validatePassword();
        let isConfirmPasswordValid = validateConfirmPassword();
        
        return isUsernameValid && isEmailValid && isPasswordValid && isConfirmPasswordValid;
    }

    /**
     * Validates the username field
     * @returns {boolean} True if valid, false otherwise
     */
    function validateUsername() {
        const username = signupUsername.value.trim();
        
        if (!username) {
            usernameError.textContent = 'Username is required';
            usernameError.classList.add('visible');
            signupUsername.classList.add('error');
            return false;
        }
        
        if (username.length < 3) {
            usernameError.textContent = 'Username must be at least 3 characters long';
            usernameError.classList.add('visible');
            signupUsername.classList.add('error');
            return false;
        }
        
        // Note: We can't check if the username already exists in real-time
        // The API will handle this check during registration
        
        usernameError.classList.remove('visible');
        signupUsername.classList.remove('error');
        return true;
    }

    /**
     * Validates the email field
     * @returns {boolean} True if valid, false otherwise
     */
    function validateEmail() {
        const email = signupEmail.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        if (!email) {
            emailError.textContent = 'Email is required';
            emailError.classList.add('visible');
            signupEmail.classList.add('error');
            return false;
        }
        
        if (!emailRegex.test(email)) {
            emailError.textContent = 'Please enter a valid email address';
            emailError.classList.add('visible');
            signupEmail.classList.add('error');
            return false;
        }
        
        // Note: We can't check if the email already exists in real-time
        // The API will handle this check during registration
        
        emailError.classList.remove('visible');
        emailError.classList.remove('visible');
        signupEmail.classList.remove('error');
        return true;
    }
    /**
     * Validates the password field
     * @returns {boolean} True if valid, false otherwise
     */
    function validatePassword() {
        const password = signupPassword.value;
        
        if (!password) {
            passwordError.textContent = 'Password is required';
            passwordError.classList.add('visible');
            signupPassword.classList.add('error');
            return false;
        }
        
        if (password.length < 8) {
            passwordError.textContent = 'Password must be at least 8 characters long';
            passwordError.classList.add('visible');
            signupPassword.classList.add('error');
            return false;
        }
        
        // Check complexity - similar to validatePasswordStrength but with error messages
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChars = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        
        if (!(hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChars)) {
            passwordError.textContent = 'Password must include uppercase and lowercase letters, numbers, and special characters';
            passwordError.classList.add('visible');
            signupPassword.classList.add('error');
            return false;
        }
        
        passwordError.classList.remove('visible');
        signupPassword.classList.remove('error');
        return true;
    }

    /**
     * Validates the confirm password field
     * @returns {boolean} True if valid, false otherwise
     */
    function validateConfirmPassword() {
        const password = signupPassword.value;
        const confirmPwd = confirmPassword.value;
        
        if (!confirmPwd) {
            confirmPasswordError.textContent = 'Please confirm your password';
            confirmPasswordError.classList.add('visible');
            confirmPassword.classList.add('error');
            return false;
        }
        
        if (password !== confirmPwd) {
            confirmPasswordError.textContent = 'Passwords do not match';
            confirmPasswordError.classList.add('visible');
            confirmPassword.classList.add('error');
            return false;
        }
        
        confirmPasswordError.classList.remove('visible');
        confirmPassword.classList.remove('error');
        return true;
    }

    /**
     * Evaluates password strength and updates the strength indicator
     */
    function validatePasswordStrength() {
        const password = signupPassword.value;
        let strength = 0;
        let feedback = '';
        
        // Check length
        if (password.length >= 8) strength += 1;
        if (password.length >= 12) strength += 1;
        
        // Check character variety
        if (/[A-Z]/.test(password)) strength += 1;  // Uppercase
        if (/[a-z]/.test(password)) strength += 1;  // Lowercase
        if (/\d/.test(password)) strength += 1;     // Numbers
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength += 1; // Special characters
        
        // Determine strength category
        passwordStrength.classList.remove('weak', 'medium', 'strong');
        
        let percentage;
        if (strength < 3) {
            passwordStrength.classList.add('weak');
            feedback = 'Too weak';
            percentage = 25;
        } else if (strength < 5) {
            passwordStrength.classList.add('medium');
            feedback = 'Moderate';
            percentage = 50;
        } else {
            passwordStrength.classList.add('strong');
            feedback = 'Strong';
            percentage = 100;
        }
        
        // Update UI
        strengthIndicator.style.width = `${percentage}%`;
        strengthText.textContent = `Password strength: ${feedback}`;
    }

    /**
     * Registers a new user with the provided information using the API
     */
    function registerUser() {
        // Show loading state
        signupButton.classList.add('btn-loading');
        signupButton.disabled = true;
        
        const username = signupUsername.value.trim();
        const email = signupEmail.value.trim();
        const password = signupPassword.value;
        const confirm_password = confirmPassword.value;
        
        // Create request data object
        const userData = {
            username,
            email,
            password,
            confirm_password
        };
        
        // API endpoint URL - use relative URL for flexibility with different environments
        const apiUrl = '/api/auth/signup';
        
        // Process account creation
        
        // Make the API call
        fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(userData),
            credentials: 'include' // Important: include credentials for cookies
        })
        .then(async response => {
            // Check if the response is JSON
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return response.json().then(data => {
                    // Return both the response status and data together
                    return { status: response.status, data };
                });
            } else {
                // If not JSON, handle text response
                try {
                    const text = await response.text();
                    return { 
                        status: response.status, 
                        data: { message: text || 'Unknown error occurred' } 
                    };
                } catch (e) {
                    // If all else fails
                    return { 
                        status: response.status, 
                        data: { message: 'Unable to parse server response' } 
                    };
                }
            }
        })
        .then(result => {
            const { status, data } = result;
            
            // Process server response
            
            // Remove loading state
            signupButton.classList.remove('btn-loading');
            signupButton.disabled = false;
            
            // Handle response based on status code
            if (status >= 200 && status < 300 && data.success) {
                // Success
                // Registration completed
                
                // Create user object for local handling
                const userId = data.data?.user?.id || data.userId || data.id || 'unknown';
                const newUser = {
                    username,
                    email,
                    userId: userId
                };
                
                // Show success message
                handleSuccessfulRegistration(newUser);
            } else {
                // Handle error response based on specific error types
                let errorMessage = data.message || 'Registration failed';
                
                // Parse specific error types
                if (errorMessage.includes('already exists')) {
                    if (errorMessage.toLowerCase().includes('email')) {
                        errorMessage = 'This email is already registered. Please use a different email.';
                        signupEmail.classList.add('error');
                        emailError.textContent = 'Email already in use';
                        emailError.classList.add('visible');
                    } else if (errorMessage.toLowerCase().includes('username')) {
                        errorMessage = 'This username is already taken. Please choose a different username.';
                        signupUsername.classList.add('error');
                        usernameError.textContent = 'Username already taken';
                        usernameError.classList.add('visible');
                    }
                } else if (status === 400) {
                    errorMessage = 'Please check your registration details and try again.';
                }
                
                // Display the error
                showAlert(signupAlert, errorMessage, 'error');
                // Handle input validation issues
                
                // Add shake animation to highlight error
                signupForm.classList.add('shake');
                setTimeout(() => {
                    signupForm.classList.remove('shake');
                }, 500);
            }
        })
        .catch(error => {
            console.error('Signup error:', error);
            // Network or parsing error
            // Handle connection issues
            
            // Remove loading state
            signupButton.classList.remove('btn-loading');
            signupButton.disabled = false;
            
            // Display more specific error message based on error type
            let errorMessage = 'Network error. Please try again later.';
            
            // Provide more specific error message if possible
            if (error.name === 'TypeError' && error.message.includes('fetch')) {
                errorMessage = 'Connection error. Please check your internet connection and try again.';
            } else if (error.name === 'SyntaxError') {
                errorMessage = 'Server returned an invalid response. Please try again later.';
            } else if (error.name === 'AbortError') {
                errorMessage = 'Request was cancelled. Please try again.';
            } else if (error.name === 'TimeoutError' || error.message.includes('timeout')) {
                errorMessage = 'Request timed out. The server may be busy, please try again later.';
            } else if (error.message && error.message.includes('CORS')) {
                errorMessage = 'Unable to connect to the server. CORS error. Please try again later.';
            }
            
            // Display the error
            showAlert(signupAlert, errorMessage, 'error');
            
            // Add shake animation to highlight error
            signupForm.classList.add('shake');
            setTimeout(() => {
                signupForm.classList.remove('shake');
            }, 500);
        });
    }

    /**
     * Handles a successful user registration
     * @param {Object} user - The newly registered user object
     */
    function handleSuccessfulRegistration(user) {
        // Hide the form
        signupForm.style.display = 'none';
        
        // Show success message
        signupSuccessAlert.innerHTML = `
            <div class="success-icon">
                <i class="fas fa-check-circle"></i>
            </div>
            <p>Account created successfully, <strong>${user.username}</strong>!</p>
            <p>Redirecting to login...</p>
        `;
        signupSuccessAlert.classList.add('visible');
        
        // Use showAlert for consistent behavior but with custom HTML and longer duration
        // This will ensure the alert gets properly cleaned up
        cleanupElementTimeouts(signupSuccessAlert);
        
        // Switch to sign-in tab after 2.5 seconds
        setTimeout(() => {
            // Reset and show the form again for future use
            signupForm.reset();
            signupForm.style.display = 'block';
            signupSuccessAlert.classList.remove('visible');
            
            // Switch to sign-in tab
            showTab('signin');
            
            // Pre-fill the username field in the sign-in form
            const signinEmail = document.getElementById('signinEmail');
            if (signinEmail) {
                signinEmail.value = user.username;
                // Focus on the password field
                const signinPassword = document.getElementById('signinPassword');
                if (signinPassword) signinPassword.focus();
            }
        }, 2500);
    }
});

// Element timeout tracking
const elementTimeouts = {};

/**
 * Cleans up any existing timeouts for an element
 * @param {HTMLElement} element - The DOM element to clean up timeouts for
 */
function cleanupElementTimeouts(element) {
    if (!element) return;
    
    const elementId = element.id || 'anonymous-element';
    
    // Clear fade timeout if it exists
    if (elementTimeouts[`${elementId}-fade`]) {
        clearTimeout(elementTimeouts[`${elementId}-fade`]);
        elementTimeouts[`${elementId}-fade`] = null;
    }
    
    // Clear dismiss timeout if it exists
    if (elementTimeouts[`${elementId}-dismiss`]) {
        clearTimeout(elementTimeouts[`${elementId}-dismiss`]);
        elementTimeouts[`${elementId}-dismiss`] = null;
    }
    
    // Reset any ongoing animations
    element.style.removeProperty('transition');
    element.style.removeProperty('opacity');
}

/**
 * Shows an alert with specified message and type, auto-dismisses after duration
 * @param {HTMLElement} element - The alert element to show
 * @param {string} message - The message to display
 * @param {string} type - The type of alert (error, success)
 * @param {number} duration - Time in ms before the alert is auto-dismissed (default: 3500)
 */
function showAlert(element, message, type = 'error', duration = 3500) {
    if (!element) return;
    
    const elementId = element.id || 'anonymous-element';
    
    // First clean up any existing timeouts for this element
    cleanupElementTimeouts(element);
    
    // Update content and make visible
    element.textContent = message;
    element.classList.remove('alert-error', 'alert-success');
    element.classList.add('visible', `alert-${type}`);
    
    // Ensure opacity is at 1 (in case it was fading)
    element.style.opacity = '1';
    
    // Set timeout to auto-dismiss
    elementTimeouts[`${elementId}-dismiss`] = setTimeout(() => {
        // Start fade out
        element.style.transition = 'opacity 0.4s ease-out';
        element.style.opacity = '0';
        
        // Remove classes after fade completes
        elementTimeouts[`${elementId}-fade`] = setTimeout(() => {
            element.classList.remove('visible', `alert-${type}`);
            element.style.removeProperty('transition');
            element.style.removeProperty('opacity');
            elementTimeouts[`${elementId}-fade`] = null;
        }, 400); // Match the fade transition duration
        
        elementTimeouts[`${elementId}-dismiss`] = null;
    }, duration);
}
