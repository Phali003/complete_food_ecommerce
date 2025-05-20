document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const elements = {
        searchProduct: document.getElementById('searchProduct'),
        searchBtn: document.getElementById('searchBtn'),
        categoryFilter: document.getElementById('categoryFilter'),
        dietaryFilter: document.getElementById('dietaryFilter'),
        priceFilter: document.getElementById('priceFilter'),
        sortBy: document.getElementById('sortBy')
    };

    // Initialize features
    initializeSpecialOffers();
    initializeSearch();
    initializeFilters();

    // Special Offers Initialization
    function initializeSpecialOffers() {
        document.querySelectorAll('.cont').forEach(product => {
            if (!product.dataset.keywords) return;
            
            const price = parseFloat(product.dataset.price || 0);
            const keywords = product.dataset.keywords.toLowerCase();
            
            if (price < 5 || 
                keywords.includes('special') || 
                keywords.includes('featured') || 
                keywords.includes('deal')) {
                product.classList.add('special-offer');
            }
        });
    }

    // Search Initialization
    function initializeSearch() {
        if (elements.searchProduct) {
            elements.searchProduct.addEventListener('input', debounce(handleSearch, 300));
        }
        if (elements.searchBtn) {
            elements.searchBtn.addEventListener('click', handleSearch);
        }
    }

    // Filter Initialization
    function initializeFilters() {
        const filters = {
            category: elements.categoryFilter,
            dietary: elements.dietaryFilter,
            price: elements.priceFilter,
            sort: elements.sortBy
        };

        Object.values(filters).forEach(filter => {
            if (filter) {
                filter.addEventListener('change', filterProducts);
            }
        });
    }

    function handleSearch() {
        if (!elements.searchProduct) return;
        
        const searchTerm = elements.searchProduct.value.toLowerCase();
        const products = document.querySelectorAll('.cont');
        let found = false;

        products.forEach(product => {
            const keywords = product.dataset.keywords?.toLowerCase() || '';
            const isVisible = !searchTerm || keywords.includes(searchTerm);
            const container = product.closest('a');
            
            if (container) {
                container.style.display = isVisible ? 'block' : 'none';
                if (isVisible) found = true;
            }
        });

        if (searchTerm && !found) {
            alert('No products found matching your search.');
        }
    }

    function filterProducts() {
        const products = document.querySelectorAll('.cont');
        const filters = {
            category: elements.categoryFilter?.value.toLowerCase() || '',
            dietary: elements.dietaryFilter?.value.toLowerCase() || '',
            price: elements.priceFilter?.value || '',
            sort: elements.sortBy?.value || ''
        };

        products.forEach(product => {
            let isVisible = true;
            const category = (product.dataset.category || '').toLowerCase();
            const dietary = (product.dataset.dietary || '').toLowerCase();
            const price = parseFloat(product.dataset.price || 0);

            if (filters.category && !category.includes(filters.category)) {
                isVisible = false;
            }
            
            if (filters.dietary && !dietary.includes(filters.dietary)) {
                isVisible = false;
            }
            
            if (filters.price) {
                switch(filters.price) {
                    case 'under-5': if (price >= 5) isVisible = false; break;
                    case '5-10': if (price < 5 || price > 10) isVisible = false; break;
                    case '10-15': if (price < 10 || price > 15) isVisible = false; break;
                    case 'above-15': if (price <= 15) isVisible = false; break;
                }
            }

            const container = product.closest('a');
            if (container) {
                container.style.display = isVisible ? 'block' : 'none';
            }
        });

        if (filters.sort) {
            sortProducts(filters.sort);
        }
    }

    function sortProducts(sortValue) {
        const container = document.querySelector('.myImages');
        if (!container) return;
        
        const products = Array.from(container.querySelectorAll('a'));
        
        products.sort((a, b) => {
            const productA = a.querySelector('.cont');
            const productB = b.querySelector('.cont');
            
            if (!productA || !productB) return 0;
            
            switch(sortValue) {
                case 'price-low':
                    return parseFloat(productA.dataset.price || 0) - parseFloat(productB.dataset.price || 0);
                case 'price-high':
                    return parseFloat(productB.dataset.price || 0) - parseFloat(productA.dataset.price || 0);
                case 'name-asc':
                    const altA = productA.querySelector('img')?.alt || '';
                    const altB = productB.querySelector('img')?.alt || '';
                    return altA.localeCompare(altB);
                default:
                    return 0;
            }
        });
        
        products.forEach(product => container.appendChild(product));
    }

    function debounce(func, wait) {
        let timeout;
        return function(...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // Enhanced Cart Functionality
    const cartManager = {
        // Cart state
        items: [],
        isAuthenticated: false,
        token: null,
        
        // Initialize cart
        init: function() {
            console.log('Starting cart initialization...');
            
            // Check if user is authenticated
            this.token = this.getAuthToken();
            this.isAuthenticated = !!this.token;
            
            // Load cart items (from API if authenticated, otherwise from localStorage)
            this.loadCart();
            
            // Add event listeners to all "Add to Cart" buttons
            const addToCartButtons = document.querySelectorAll('.addToCart');
            console.log('Found Add to Cart buttons:', addToCartButtons.length);
            
            addToCartButtons.forEach(button => {
                button.addEventListener('click', (event) => {
                    console.log('Add to Cart clicked:', {
                        itemId: button.getAttribute('data-item-id'),
                        itemName: button.getAttribute('data-item-name'),
                        itemPrice: button.getAttribute('data-item-price')
                    });
                    this.handleAddToCart(event);
                });
            });
            
            // Create cart count indicator if it doesn't exist
            this.createCartCountElement();
            
            // Update UI
            this.updateUI();
            
            console.log('Cart initialized:', {
                isAuthenticated: this.isAuthenticated,
                itemCount: this.items.length
            });
        },
        
        // Get auth token from cookies
        getAuthToken: function() {
            const tokenCookie = document.cookie.split('; ').find(cookie => cookie.startsWith('token='));
            return tokenCookie ? tokenCookie.split('=')[1] : null;
        },
        
        // Load cart data
        loadCart: function() {
            if (this.isAuthenticated) {
                // Load from API if authenticated
                this.fetchCartFromAPI();
            } else {
                // Load from localStorage if not authenticated
                this.items = JSON.parse(localStorage.getItem('cart')) || [];
                this.updateUI();
            }
        },
        
        // Fetch cart from API (for authenticated users)
        fetchCartFromAPI: function() {
            fetch('/api/cart', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to fetch cart');
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Map API response to our cart format
                    this.items = data.data.items.map(item => ({
                        id: item.product_id.toString(),
                        name: item.name,
                        price: parseFloat(item.price),
                        quantity: item.quantity,
                        image_url: item.image_url
                    }));
                    this.updateUI();
                }
            })
            .catch(error => {
                console.error('Error fetching cart:', error);
                // Fall back to local storage if API fails
                this.items = JSON.parse(localStorage.getItem('cart')) || [];
                this.updateUI();
            });
        },
        
        // Save cart (to API if authenticated, otherwise to localStorage)
        saveCart: function() {
            if (!this.isAuthenticated) {
                localStorage.setItem('cart', JSON.stringify(this.items));
            }
            this.updateUI();
        },
        
        // Add item to cart (via API if authenticated)
        addItem: function(itemData) {
            console.log('Adding item to cart:', itemData);
            
            if (this.isAuthenticated) {
                console.log('User authenticated, using API');
                // Add via API
                fetch('/api/cart/items', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.token}`
                    },
                    body: JSON.stringify({
                        product_id: parseInt(itemData.id),
                        quantity: 1
                    })
                })
                .then(response => {
                    console.log('API response status:', response.status);
                    if (!response.ok) {
                        throw new Error('Failed to add item to cart');
                    }
                    return response.json();
                })
                .then(data => {
                    console.log('API response data:', data);
                    if (data.success) {
                        // Refresh cart from API
                        this.fetchCartFromAPI();
                    }
                })
                .catch(error => {
                    console.error('Error adding item to cart:', error);
                    this.showError('Failed to add item to cart');
                });
            } else {
                console.log('User not authenticated, using localStorage');
                // Add to local cart
                const existingItemIndex = this.items.findIndex(item => item.id === itemData.id);
                
                if (existingItemIndex > -1) {
                    // Item exists, increment quantity
                    this.items[existingItemIndex].quantity = (this.items[existingItemIndex].quantity || 1) + 1;
                    console.log('Increased quantity for existing item:', this.items[existingItemIndex]);
                } else {
                    // Add new item to cart
                    const newItem = {
                        id: itemData.id,
                        name: itemData.name,
                        price: itemData.price,
                        quantity: 1
                    };
                    this.items.push(newItem);
                    console.log('Added new item to cart:', newItem);
                }
                
                this.saveCart();
                console.log('Updated cart saved to localStorage:', this.items);
            }
        },
        
        // Remove item from cart
        removeItem: function(itemId) {
            if (this.isAuthenticated) {
                // Remove via API
                fetch(`/api/cart/items/${itemId}`, {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.token}`
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to remove item from cart');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        // Refresh cart from API
                        this.fetchCartFromAPI();
                    }
                })
                .catch(error => {
                    console.error('Error removing item from cart:', error);
                });
            } else {
                // Remove from local cart
                this.items = this.items.filter(item => item.id !== itemId);
                this.saveCart();
            }
        },
        
        // Clear entire cart
        clearCart: function() {
            if (this.isAuthenticated) {
                // Clear via API
                fetch('/api/cart', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.token}`
                    }
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Failed to clear cart');
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        this.items = [];
                        this.updateUI();
                    }
                })
                .catch(error => {
                    console.error('Error clearing cart:', error);
                });
            } else {
                // Clear local cart
                this.items = [];
                this.saveCart();
            }
        },
        
        // Handler for add to cart button clicks
        handleAddToCart: function(event) {
            event.preventDefault();
            event.stopPropagation();
            
            const button = event.currentTarget;
            const itemId = button.getAttribute('data-item-id');
            const itemName = button.getAttribute('data-item-name');
            const itemPrice = parseFloat(button.getAttribute('data-item-price'));
            
            // Add item to cart
            this.addItem({
                id: itemId,
                name: itemName,
                price: itemPrice
            });
            
            // Show visual feedback
            this.showAddedFeedback(button);
        },
        
        // Calculate cart totals
        getCartTotals: function() {
            return {
                quantity: this.items.reduce((total, item) => total + (item.quantity || 1), 0),
                price: this.items.reduce((total, item) => total + (item.price * (item.quantity || 1)), 0).toFixed(2)
            };
        },
        
        // Create cart count element if it doesn't exist
        createCartCountElement: function() {
            // Check if cart count element already exists
            if (document.querySelector('.cart-count')) return;
            
            // Find cart link element
            const navElement = document.querySelector('.commerceContainer ul');
            if (!navElement) return;
            
            const cartLi = navElement.querySelector('li:nth-child(2)');
            if (!cartLi) return;
            
            const cartLink = cartLi.querySelector('a');
            if (!cartLink) return;
            
            // Create and append cart count element
            const countSpan = document.createElement('span');
            countSpan.className = 'cart-count';
            countSpan.textContent = '0';
            countSpan.style.display = 'none';
            countSpan.style.backgroundColor = '#ff0';
            countSpan.style.color = '#363636';
            countSpan.style.borderRadius = '50%';
            countSpan.style.padding = '0.2em 0.5em';
            countSpan.style.marginLeft = '0.5em';
            countSpan.style.fontSize = '0.8em';
            countSpan.style.fontWeight = 'bold';
            cartLink.appendChild(countSpan);
        },
        
        // Update UI elements with current cart state
        updateUI: function() {
            const totals = this.getCartTotals();
            
            // Update cart count display
            const cartCountElement = document.querySelector('.cart-count');
            if (cartCountElement) {
                cartCountElement.textContent = totals.quantity;
                cartCountElement.style.display = totals.quantity > 0 ? 'inline-block' : 'none';
            }
            
            // Additional UI updates can be added here
        },
        
        // Show visual feedback when item is added to cart
        showAddedFeedback: function(button) {
            // Save original button text
            const originalText = button.textContent.trim();
            const originalBackground = button.style.backgroundColor;
            const originalColor = button.style.color;
            
            // Change button text and style
            button.textContent = 'Added to Cart!';
            button.style.backgroundColor = '#ff0';
            button.style.color = '#363636';
            
            // Add animation if supported
            button.classList.add('pulse-animation');
            
            // Reset after a delay
            setTimeout(() => {
                button.textContent = originalText;
                button.style.backgroundColor = originalBackground;
                button.style.color = originalColor;
                button.classList.remove('pulse-animation');
            }, 1000);
        },
        
        // Show error message
        showError: function(message) {
            alert(message);
        }
    };
    
    // Initialize cart system
    initializeCart();
    
    function initializeCart() {
        cartManager.init();
    }
});
