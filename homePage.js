const signButton = document.getElementById("signBtn");
const signUpModal = document.getElementById("signUpModal");
const signInModal = document.getElementById("signInModal");
const closeSignUpModal = document.getElementById("closeSignUp");
const closeSignInModal = document.getElementById("closeSignIn");
const switchToSignUp = document.getElementById("switchToSignUp");
const switchToSignIn = document.getElementById("switchToSignIn");

signButton.onclick = function (){
    signUpModal.style.display = "block";
}

closeSignUpModal.onclick = function (){
    signUpModal.style.display = "none";
}

closeSignInModal.onclick = function(){
    signInModal.style.display = "none";
}
switchToSignIn.onclick = function(){
    signUpModal.style.display = "none";
    signInModal.style.display = "block";
}
switchToSignUp.onclick = function (){
    signInModal.style.display = "none";
    signUpModal.style.display = "block";
}
window.onclick = function (event){
    if(event.target == signUpModal){
        signUpModal.style.display = "none";
    }
    if(event.target == signInModal){
        signInModal.style.display = "none";
    }
}

document.addEventListener("DOMContentLoaded", function() {
    const browseProducts = document.getElementById("browseProduct");
    const searchProduct = document.getElementById("searchProduct");
    const searchButton = document.getElementById("searchBtn");

    browseProducts.addEventListener("click", function(event) {
        event.preventDefault();
        console.log('Browse Products clicked');
        
        // Apply styles and classes
        searchProduct.classList.add("browseProduct");
        searchProduct.style.display = "block"; 
        searchProduct.style.marginLeft = "2.6em";
        searchButton.style.display = "block"; 
        searchButton.style.marginTop = "2em"; 
        searchButton.style.marginRight = "2em";
        
        // Focus and scroll into view
        searchButton.focus();
        searchProduct.focus();
        searchProduct.scrollIntoView({ behavior: 'smooth', block: 'start' });
        
        // Log current styles to verify if they are being applied
        console.log('searchProduct styles:', getComputedStyle(searchProduct).cssText);
        console.log('searchButton styles:', getComputedStyle(searchButton).cssText);
    });
});
let resetButton = document.getElementById("resetBtn");
let searchButton = document.getElementById("searchBtn");
searchButton.addEventListener("click", function() {
    let searchProduct = document.getElementById("searchProduct").value.toLowerCase();
    let found = false;
    let products = document.querySelectorAll(".myImages .cont");

    // Reset display for all products
    products.forEach(function(product) {
        product.style.display = "inline-flex";
        product.classList.add("foundProduct"); // Reset display
    });

    products.forEach(function(product) {
        let keywords = product.getAttribute("data-keywords").toLowerCase();
        if (keywords.includes(searchProduct)) {
            product.classList.add("foundProduct-reset");
            product.style.display = "inline-flex";
           
            
            found = true;
        } else {
            product.style.display = "none";
        }
    });

    if (!found) {
        alert("Product not found!");
        products.forEach(function(product) {
            product.style.display = "inline-flex";
            product.classList.add(".myImages");
        });
    }
    document.getElementById("searchProduct").value = "";
    document.getElementById("foundProduct").value = "";
});

// Allow "Enter" key to trigger search
document.getElementById("searchProduct").addEventListener("keypress", function(event) {
    if (event.key === "Enter") {
        searchButton.click();
    }
});

// Reset functionality
resetButton.addEventListener("click", function() {
    document.getElementById("searchProduct").value = ""; // Clears the search input.
    let products = document.querySelectorAll(".myImages .cont");
    products.forEach(function(product) {
        product.style.display = "inline-block"; // Reset display for all products
        product.classList.add("foundProduct"); // Remove foundProduct class
    });
});

// Browse product implementation
document.addEventListener("DOMContentLoaded", function() {
    const browseProducts = document.getElementById("browseProduct");
    const searchProduct = document.getElementById("searchProduct");
    const searchButton = document.getElementById("searchBtn");
    browseProducts.addEventListener("click", function(event) {
        event.preventDefault();
        console.log('Browse Products clicked');

        // Apply styles and classes
        searchProduct.classList.add("browseProduct");
        searchProduct.style.display = "block";
        searchProduct.style.marginLeft = "4.2em";
        searchButton.style.display = "block";
        searchButton.style.marginTop = "1.2em";
        searchButton.style.marginRight = "";

        // Focus and scroll into view
        searchButton.focus();
        searchProduct.focus();
        searchProduct.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Log current styles to verify if they are being applied
        console.log('searchProduct styles:', getComputedStyle(searchProduct).cssText);
        console.log('searchButton styles:', getComputedStyle(searchButton).cssText);
    });
});



//Add to cart functionality

let addbuttons = document.querySelectorAll(".addToCart");
let cartList = document.getElementById("cartList");

addbuttons.forEach(button => {
    button.addEventListener("click", addToCart);
});
function addToCart(event) {
    e.preventDefault();
    let itemName = event.target.getAttribute("data-item-name");
    let itemPrice = event.target.getAttribute("data-item-price");
    let cart = JSON.parse(localStorage.getItem("cart")) || [];
    cart.push({name: itemName, price: itemPrice});
    localStorage.setItem("cart", JSON.stringify(cart));
    
    const listItems = document.createElement("li");
    listItems.textContent = `${itemName} - $${itemPrice}`;
    alert(`${itemName} added to cart successfully!`);
    cartList.appendChild(listItems);

    let products = document.querySelectorAll(".myImages .cont");
    products.forEach(function(product) {
        product.style.display = "inline-flex"; 
        product.classList.remove("foundProduct"); 
        product.style.top = "-20em";
        product.style.position = "";
        product.style.zIndex = "";
    });
    
    const deleteButton = document.createElement("button");
    deleteButton.textContent = "Remove item";
    listItems.appendChild(deleteButton);

    deleteButton.addEventListener("click", function() {
        listItems.remove();
        // Update the cart in localStorage for a removed item
        cart = cart.filter(item => item.name !== itemName);
        localStorage.setItem("cart", JSON.stringify(cart));
    });

    // Reset display for all products
 
}
