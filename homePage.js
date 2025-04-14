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

    // Cart Functionality
    initializeCart();
    
    function initializeCart() {
        // Initialize cart in localStorage if it doesn't exist
        if (!localStorage.getItem('cart')) {
            localStorage.setItem('cart', JSON.stringify([]));
        }
        
        // Add event listeners to all "Add to Cart" buttons
        const addToCartButtons = document.querySelectorAll('.addToCart');
        addToCartButtons.forEach(button => {
            button.addEventListener('click', addToCart);
        });
        
        // Update cart count display
        updateCartCount();
    }
    
    function addToCart(event) {
        event.preventDefault();
        event.stopPropagation();
        
        const button = event.target;
        const itemId = button.getAttribute('data-item-id');
        const itemName = button.getAttribute('data-item-name');
        const itemPrice = parseFloat(button.getAttribute('data-item-price'));
        
        // Get current cart from localStorage
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        
        // Check if item is already in cart
        const existingItemIndex = cart.findIndex(item => item.id === itemId);
        
        if (existingItemIndex > -1) {
            // Item exists, increment quantity
            cart[existingItemIndex].quantity = (cart[existingItemIndex].quantity || 1) + 1;
        } else {
            // Add new item to cart
            cart.push({
                id: itemId,
                name: itemName,
                price: itemPrice,
                quantity: 1
            });
        }
        
        // Save updated cart back to localStorage
        localStorage.setItem('cart', JSON.stringify(cart));
        
        // Visual feedback
        showAddedFeedback(button);
        
        // Update cart count
        updateCartCount();
    }
    
    function updateCartCount() {
        const cart = JSON.parse(localStorage.getItem('cart')) || [];
        const totalItems = cart.reduce((total, item) => total + (item.quantity || 1), 0);
        
        // Update cart count display if it exists
        const cartCountElement = document.querySelector('.cart-count');
        if (cartCountElement) {
            cartCountElement.textContent = totalItems;
            cartCountElement.style.display = totalItems > 0 ? 'inline-block' : 'none';
        } else {
            // Create cart count element if it doesn't exist
            const navElement = document.querySelector('.commerceContainer ul');
            if (navElement) {
                const cartLi = navElement.querySelector('li:nth-child(2)');
                if (cartLi) {
                    const cartLink = cartLi.querySelector('a');
                    if (cartLink) {
                        const countSpan = document.createElement('span');
                        countSpan.className = 'cart-count';
                        countSpan.textContent = totalItems;
                        countSpan.style.display = totalItems > 0 ? 'inline-block' : 'none';
                        countSpan.style.backgroundColor = '#ff0';
                        countSpan.style.color = '#363636';
                        countSpan.style.borderRadius = '50%';
                        countSpan.style.padding = '0.2em 0.5em';
                        countSpan.style.marginLeft = '0.5em';
                        countSpan.style.fontSize = '0.8em';
                        countSpan.style.fontWeight = 'bold';
                        cartLink.appendChild(countSpan);
                    }
                }
            }
        }
    }
    
    function showAddedFeedback(button) {
        // Save original button text
        const originalText = button.textContent;
        
        // Change button text and style
        button.textContent = 'Added to Cart!';
        button.style.backgroundColor = '#ff0';
        button.style.color = '#363636';
        
        // Reset after a delay
        setTimeout(() => {
            button.textContent = originalText;
            button.style.backgroundColor = '';
            button.style.color = '';
        }, 1000);
    }
});
