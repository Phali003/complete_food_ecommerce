function storeUserDetails() {
  const addressInput = document.getElementById("address").value;
  const cityInput = document.getElementById("city").value;
  const countryInput = document.getElementById("country").value;
  const fullAddress = `${addressInput}, ${cityInput}, ${countryInput}`;
  const userDetails = {
    address: fullAddress,
  };
  //Store the user details in localStorage

  localStorage.setItem("userDetails", JSON.stringify(userDetails));
  return fullAddress;
}

document.addEventListener("DOMContentLoaded", function () {
  const checkOutList = document.getElementById("checkOut");
  let cart = JSON.parse(localStorage.getItem("cart")) || [];
  cart.forEach(function (product) {
    const li = document.createElement("li");
    li.textContent = `${product.name} = $${product.price}`;
    checkOutList.appendChild(li);
  });

  // Automatically calculate and display the total price on page load
  calculateTotal();
});

function calculateTotal() {
  let total = 0;
  const cart = JSON.parse(localStorage.getItem("cart")) || [];
  cart.forEach(function (product) {
    total += parseFloat(product.price);
  });
  document.getElementById("total-amount").textContent = total.toFixed(2);
}

let inputs = document.querySelectorAll(".inputs");
inputs.forEach((input) => {
  input.addEventListener("input", function () {
    if (this.value) {
      input.classList.add("inputLabel");
    } else {
      input.classList.remove("inputLabel");
    }
  });
});

let place_order = document.querySelector(".placeOrder");
place_order.addEventListener("click", function () {
  const signInUser = document.getElementById("signInUsername").value;
  const signInEmail = document.getElementById("signInEmail").value;
  const phoneInput = document.getElementById("phoneNumber");
  const addressInput = document.getElementById("address");
  const cityInput = document.getElementById("city");
  const countryInput = document.getElementById("country");

  const isPhoneValid = validatePhoneNumber();
  const isAddressValid = validateAddress(addressInput.value);
  const isCityValid = validateCity(cityInput.value);
  const isCountryValid = validateCountry(countryInput.value);

  if (
    validateInUsername(signInUser) &&
    validateInEmail(signInEmail) &&
    isPhoneValid &&
    isAddressValid &&
    isCityValid &&
    isCountryValid
  ) {
    // Pass values
    const fullAddress = storeUserDetails();
    const items = document.querySelectorAll("li");
    let orderDetails = `The following products have been ordered successfully, ${signInUser}:\n`;
    items.forEach((item) => {
      orderDetails += item.textContent + "\n";
    });
    alert(orderDetails);
    document.getElementById("signInEmail").value = "";
    document.getElementById("signInUsername").value = "";
    phoneInput.value = "";
    cityInput.value = "";
    addressInput.value = "";
    countryInput.value = "";
  } else {
    alert("Please fill in all required fields!");
    return false;
  }
});

function validateInEmail(signInEmail) {
  const check_signInEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!check_signInEmail.test(signInEmail)) {
    alert("Email must contain @ before domain name");
    return false;
  }
  return true;
}

function validateInUsername(signInUser) {
  const check_signInUsername = /^[A-Z][a-zA-Z0-9]{5,}$/;
  if (!check_signInUsername.test(signInUser)) {
    alert(
      "Username must start with a capital and not be less than 5 characters",
    );
    return false;
  }
  return true;
}

function validatePhoneNumber() {
  const phoneInput = document.getElementById("phoneNumber");
  let phoneNumber = phoneInput.value;
  //Remove non-numeric characters except '+' for international numbers
  phoneNumber = phoneNumber.replace(/(?!^\+)\D/g, "");
  //Update the input field with the cleaned phone number
  phoneInput.value = phoneNumber;
  //Check if phone number is valid
  if (phoneNumber.length < 10) {
    alert("Please enter a valid number");
    return false;
  }
  return true;
}
function validateAddress(address) {
  return address.trim() !== "";
}
function validateCity(city) {
  return city.trim() !== "";
}
function validateCountry(country) {
  return country.trim() !== "";
}
