import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './Login.css';

// Configure axios defaults for cross-origin requests
axios.defaults.withCredentials = true;
axios.defaults.headers.common['Accept'] = 'application/json';

const Login = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    identifier: '', // Can be email or username
    password: ''
  });
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      // Prepare login data
      const loginData = {
        password: formData.password
      };
      
      // Check if identifier is email or username
      if (formData.identifier.includes('@')) {
        loginData.email = formData.identifier;
      } else {
        loginData.username = formData.identifier;
      }

      // Send login request with credential support
      const response = await axios.post('/api/auth/login', loginData, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      });
      
      if (response.data.success) {
        // Store auth data
        localStorage.setItem('token', response.data.token);
        localStorage.setItem('userId', response.data.userId);
        localStorage.setItem('username', response.data.username);
        localStorage.setItem('userRole', response.data.role);
        
        // Set auth header for future requests
        axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
        
        // Log the role for debugging
        console.log(`User authenticated with role: ${response.data.role}`);
        
        // Redirect based on user role
        if (response.data.role === 'admin' || response.data.isAdmin) {
          navigate('/admin/dashboard');
        } else {
          navigate('/user/dashboard');
        }
      }
    } catch (err) {
      console.error('Login error:', err);
      
      // More detailed error handling
      let errorMessage;
      
      if (err.response) {
        // Server responded with an error
        if (err.response.status === 500) {
          errorMessage = 'Server error. Please try again later.';
        } else if (err.response.status === 401 || err.response.status === 403) {
          errorMessage = 'Invalid credentials. Please check your email/username and password.';
        } else if (err.response.data && err.response.data.message) {
          errorMessage = err.response.data.message;
        } else {
          errorMessage = 'Login failed. Please check your credentials.';
        }
      } else if (err.request) {
        // Request was made but no response received (network error)
        errorMessage = 'Unable to connect to the server. Please check your internet connection.';
      } else {
        // Something else caused the error
        errorMessage = 'An unexpected error occurred. Please try again.';
      }
      
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-box">
        <h2>Login</h2>
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="identifier">Email or Username</label>
            <input
              type="text"
              id="identifier"
              name="identifier"
              value={formData.identifier}
              onChange={handleChange}
              required
              placeholder="Enter your email or username"
              className="form-control"
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
              placeholder="Enter your password"
              className="form-control"
            />
          </div>
          
          <button 
            type="submit"
            className="login-button"
            disabled={loading}
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
        
        <div className="login-footer">
          <p>Don't have an account? <a href="/signup">Sign up</a></p>
          <p><a href="/admin-setup">Setup admin account</a></p>
        </div>
      </div>
    </div>
  );
};

export default Login;

