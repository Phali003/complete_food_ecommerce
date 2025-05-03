document.addEventListener("DOMContentLoaded", function() {
    // Print functionality
    const printButton = document.querySelector('.print-order');
    if (printButton) {
        printButton.addEventListener('click', function() {
            window.print();
        });
    }

    // Generate order number
    function generateOrderNumber() {
        const timeStamp = Date.now();
        const randomNumber = Math.floor(Math.random() * 1000000);
        return `ORD-${timeStamp}-${randomNumber}`;
    }

    // Get order date
    function getOrderDate() {
        const today = new Date();
        return today.toDateString();
    }

    // Get order address
    function getOrderAddress() {
        const userDetails = JSON.parse(localStorage.getItem("userDetails"));
        return userDetails ? userDetails.address : "No address provided";
    }

    // Update order details
    const orderNumberElement = document.getElementById("order-number");
    const orderDateElement = document.getElementById("order-date");
    const orderAddressElement = document.getElementById("delivery-address");

    if (orderNumberElement) orderNumberElement.textContent = generateOrderNumber();
    if (orderDateElement) orderDateElement.textContent = getOrderDate();
    if (orderAddressElement) orderAddressElement.textContent = getOrderAddress();
});
