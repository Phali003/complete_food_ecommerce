function generateOrderNumber() {
  // Get the current timestamp
  const timeStamp = Date.now();
  // Generate a random number
  const randomNumber = Math.floor(Math.random() * 1000000);
  // Combine both timestamp and random number to generate order number
  const orderNumber = `ORD-${timeStamp}-${randomNumber}`;
  return orderNumber;
}

function getOrderDate() {
  // Get the current date
  const today = new Date();
  return today.toDateString();
}

function getOrderAddress() {
  // Retrieve address values stored in localStorage
  const userDetails = JSON.parse(localStorage.getItem("userDetails"));
  return userDetails ? userDetails.address : "No address provided";
}

// Display the generated order number when the page loads
document.addEventListener("DOMContentLoaded", function () {
  const orderNumberElement = document.getElementById("orderNumber");
  orderNumberElement.textContent = generateOrderNumber();

  const orderDateElement = document.getElementById("orderDate");
  orderDateElement.textContent = getOrderDate();

  const orderAddressElement = document.getElementById("orderAddress");
  orderAddressElement.textContent = getOrderAddress();
});
