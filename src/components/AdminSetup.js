import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './AdminSetup.css';

/**
 * Initial Admin Setup Component
 * 
 * This component allows for setting up the first admin account
 * when the application is first deployed. It checks if an admin
 * already exists and only allows setup if none exists.
 */
const AdminSetup = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    setupCode: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [checkingAdmins, setCheckingAdmins] = useState(true);
  const [adminExists, setAdminExists] = useState(false);

  useEffect(() => {
    // Check if any admin already exists
    const checkAdminExists = async () => {
      try {
        const response = await axios.get('/api/auth/check-admin-exists');
        setAdminExists(response.data.exists);
      } catch (error) {
        console.error('Error checking admin existence:', error);
        // For security, if we can't check, assume an admin exists
        setAdminExists(true);
      } finally {
        setCheckingAdmins(false);
      }
    };

    checkAdminExists();
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    // Basic validation
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    try {
      // Submit admin setup request
      const response = await axios.post('/api/auth/setup-initial-admin', {
        username: formData.username,
        email: formData.email,
        password: formData.password,
        setupCode: formData.setupCode
      });

      if (response.data.success) {
        setSuccess('Admin account created successfully!');
        
        // Store authentication token if provided
        if (response.data.token) {
          localStorage.setItem('token', response.data.token);
        }
        
        // Redirect to admin dashboard after short delay
        setTimeout(() => {
          navigate('/admin/dashboard');
        }, 2000);
      }
    } catch (err) {
      console.error('Admin setup error:', err);
      setError(
        err.response?.data?.message || 
        'Failed to create admin account. Please check your details and try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  // Show loading state while checking for existing admins
  if (checkingAdmins) {
    return (
      <div className="admin-setup-container">
        <div className="admin-setup-card">
          <h2>Checking System Status...</h2>
          <div className="loader"></div>
        </div>
      </div>
    );
  }

  // If admin already exists, show notification
  if (adminExists) {
    return (
      <div className="admin-setup-container">
        <div className="admin-setup-card">
          <h2>Admin Setup Not Available</h2>
          <p>An administrator account already exists in the system.</p>
          <p>
            Please contact your system administrator or log in with an existing admin account.
          </p>
          <div className="setup-buttons">
            <button onClick={() => navigate('/login')} className="login-button">
              Go to Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="admin-setup-container">
      <div className="admin-setup-card">
        <h2>Initial Admin Setup</h2>
        <p className="setup-info">
          Create the first administrator account for your Food E-commerce platform.
          You'll need the special setup code provided during deployment.
        </p>
        
        {error && <div className="error-message">{error}</div>}
        {success && <div className="success-message">{success}</div>}
        
        <form onSubmit={handleSubmit} className="admin-setup-form">
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              required
              minLength={3}
              maxLength={30}
              placeholder="Admin username"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              required
              placeholder="Admin email address"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
              minLength={8}
              placeholder="Create a strong password"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password</label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              required
              placeholder="Confirm your password"
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="setupCode">Admin Setup Code</label>
            <input
              type="password"
              id="setupCode"
              name="setupCode"
              value={formData.setupCode}
              onChange={handleChange}
              required
              placeholder="Enter the secure setup code"
            />
            <small className="setup-code-info">
              This is the secure code that was provided during system deployment.
            </small>
          </div>
          
          <button 
            type="submit" 
            className="setup-button"
            disabled={loading}
          >
            {loading ? 'Creating Admin Account...' : 'Create Admin Account'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default AdminSetup;

