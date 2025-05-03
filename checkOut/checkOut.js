// Navigation control functions
function enableConfirmationStep() {
  const confirmationStep = document.getElementById("confirmation-step");
  if (confirmationStep) {
    confirmationStep.classList.remove("disabled");
    confirmationStep.classList.remove("tooltip");
    // Update the href to ensure proper navigation
    confirmationStep.setAttribute("href", "../confirmation/confirm.html");
  }
}

function disableConfirmationStep() {
  const confirmationStep = document.getElementById("confirmation-step");
  if (confirmationStep) {
    // Add disabled state classes and styles
    confirmationStep.classList.add("disabled");
    confirmationStep.classList.add("tooltip");
    confirmationStep.style.cursor = "not-allowed";
    confirmationStep.style.opacity = "0.6";

    // Check cart state for appropriate message
    const cart = JSON.parse(localStorage.getItem("cart") || "[]");
    const message =
      cart.length === 0
        ? "Please add items to your cart before proceeding to confirmation"
        : "Please complete checkout before proceeding to confirmation";

    // Remove any existing tooltip text
    const existingTooltip = confirmationStep.querySelector(".tooltip-text");
    if (existingTooltip) {
      existingTooltip.remove();
    }

    // Add tooltip text
    const tooltipText = document.createElement("span");
    tooltipText.className = "tooltip-text";
    tooltipText.textContent = message;
    confirmationStep.appendChild(tooltipText);

    // Remove any existing event listeners first
    const newConfirmationStep = confirmationStep.cloneNode(true);
    confirmationStep.parentNode.replaceChild(
      newConfirmationStep,
      confirmationStep
    );

    // Add click prevention with appropriate message
    newConfirmationStep.addEventListener("click", function (e) {
      e.preventDefault();
      showErrorNotification(message);
    });
  }
}
// Store order data for confirmation page
function generateOrderId() {
  const date = new Date();
  const year = date.getFullYear().toString().slice(2);
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const random = Math.floor(Math.random() * 10000)
    .toString()
    .padStart(5, "0");
  return `FD-${year}${month}${day}-${random}`;
}

function storeOrderData(cart, userDetails, totalAmount) {
  const orderData = {
    orderId: generateOrderId(),
    items: cart,
    userDetails: userDetails,
    totalAmount: totalAmount,
    orderDate: new Date().toISOString(),
    estimatedDelivery: new Date(Date.now() + 60 * 60 * 1000).toISOString(), // 1 hour delivery time
  };

  sessionStorage.setItem("orderData", JSON.stringify(orderData));
  // Backup in localStorage in case sessionStorage is cleared
  localStorage.setItem("orderData", JSON.stringify(orderData));

  return orderData;
}

function storeUserDetails() {
  const addressInput = document.getElementById("address").value;
  const cityInput = document.getElementById("city").value;
  const countryInput = document.getElementById("country").value;
  const fullAddress = `${addressInput}, ${cityInput}, ${countryInput}`;
  const userDetails = {
    address: fullAddress,
    name: document.getElementById("signInUsername").value,
    email: document.getElementById("signInEmail").value,
    phone: document.getElementById("phoneNumber").value,
  };
  //Store the user details in localStorage

  localStorage.setItem("userDetails", JSON.stringify(userDetails));
  return fullAddress;
}
document.addEventListener("DOMContentLoaded", function () {
  console.log("DOM fully loaded, initializing checkout page...");

  // Check navigation state
  initNavigationState();

  // Render the cart with improved display
  try {
    renderOrderSummary();
    console.log("Order summary rendering complete");
  } catch (error) {
    console.error("Error rendering order summary:", error);
  }

  // Make sure ALL notifications are hidden on page load
  const notifications = document.querySelectorAll(".notification");
  notifications.forEach((notification) => {
    notification.classList.remove("show");
    notification.style.display = "none";
    notification.style.opacity = "0";
    notification.style.visibility = "hidden";
  });

  // Add notification close event listeners with improved functionality
  const notificationCloseButtons = document.querySelectorAll(
    ".notification-close"
  );
  notificationCloseButtons.forEach((button) => {
    // Remove any existing listeners to prevent duplicates
    button.removeEventListener("click", closeNotification);
    // Add the event listener
    button.addEventListener("click", closeNotification);
  });

  // Add CSS for notification transitions if not already present
  if (!document.getElementById("notification-styles")) {
    const styleElement = document.createElement("style");
    styleElement.id = "notification-styles";
    styleElement.textContent = `
      .notification {
        transition: opacity 0.3s ease, visibility 0.3s ease, transform 0.3s ease;
      }
      .notification.show {
        opacity: 1 !important;
        visibility: visible !important;
        display: flex !important;
      }
    `;
    document.head.appendChild(styleElement);
  }

  // Set up payment method selection
  const paymentMethods = document.querySelectorAll(".payment-method");
  paymentMethods.forEach((method) => {
    method.addEventListener("click", function () {
      paymentMethods.forEach((m) => m.classList.remove("selected"));
      this.classList.add("selected");

      // Set aria-checked for accessibility
      paymentMethods.forEach((m) => m.setAttribute("aria-checked", "false"));
      this.setAttribute("aria-checked", "true");
    });
  });
});

// Initialize navigation state
function initNavigationState() {
  // Check if an order has been completed and cart has items
  const orderCompleted = sessionStorage.getItem("orderCompleted") === "true";
  const cart = JSON.parse(localStorage.getItem("cart") || "[]");

  if (orderCompleted && cart.length > 0) {
    enableConfirmationStep();
  } else {
    disableConfirmationStep();
  }
}

// Validate cart data before processing
function validateCart(cart) {
  if (!Array.isArray(cart) || cart.length === 0) {
    return false;
  }

  // Check if all cart items have the required properties
  return cart.every((item) => {
    return (
      item &&
      typeof item === "object" &&
      typeof item.name === "string" &&
      !isNaN(parseFloat(item.price))
    );
  });
}

// Render the order summary with detailed cart information
function renderOrderSummary() {
  console.log("Rendering order summary...");

  // Get DOM elements
  const checkOutList = document.getElementById("checkOutList");
  const subtotalElement = document.getElementById("subtotalAmount");
  const taxElement = document.getElementById("taxAmount");
  const totalElement = document.getElementById("totalAmount");

  if (!checkOutList || !subtotalElement || !taxElement || !totalElement) {
    console.error("Required DOM elements not found for order summary");
    return;
  }

  // Clear the checkout list
  checkOutList.innerHTML = "";

  // Initialize subtotal
  let subtotal = 0;
  let cart = [];

  try {
    // Get cart data from localStorage
    const cartData = localStorage.getItem("cart");

    // Check if cart data exists
    if (!cartData) {
      console.log("No cart data found");
      cart = [];
    } else {
      // Try to parse the cart data
      cart = JSON.parse(cartData);

      // Validate cart data only if it's not empty
      if (cart.length > 0 && !validateCart(cart)) {
        console.warn("Invalid cart data detected");
        cart = [];
      }
    }
  } catch (error) {
    console.error("Error loading cart:", error);
    cart = [];
  }

  // Check if cart is empty
  if (cart.length === 0) {
    console.log("Cart is empty, displaying empty cart message");
    const emptyMessage = document.createElement("li");
    emptyMessage.className = "checkout-item empty-cart";
    emptyMessage.innerHTML = `
      <span class="item-name">Your cart is currently empty. <a href="/" style="color: #3a6ea5; text-decoration: underline;">Browse our menu</a> to add items.</span>
    `;
    checkOutList.appendChild(emptyMessage);

    // Update total displays with zeros
    subtotalElement.textContent = "$0.00";
    taxElement.textContent = "$0.00";
    totalElement.textContent = "$0.00";

    // Add a button to go to menu
    const orderSummary = document.querySelector(".order-summary");
    if (orderSummary) {
      let menuButton = document.querySelector(".empty-cart-button");
      if (!menuButton) {
        menuButton = document.createElement("a");
        menuButton.href = "/";
        menuButton.style.maxWidth = "300px";
        menuButton.style.margin = "1rem auto";
        menuButton.style.display = "block";
        menuButton.style.textAlign = "center";
        menuButton.style.background = "var(--primary)";
        menuButton.textContent = "Browse Our Menu";
        orderSummary.appendChild(menuButton);
      }
    }

    return;
  }

  // Check if cart items have quantity property
  cart = cart.map((item) => {
    // Create a copy to avoid modifying the original
    const newItem = { ...item };

    // Set default quantity if not present or invalid
    if (
      !newItem.quantity ||
      isNaN(parseInt(newItem.quantity)) ||
      parseInt(newItem.quantity) < 1
    ) {
      newItem.quantity = 1;
    }

    return newItem;
  });

  // Render each cart item
  cart.forEach(function (product, index) {
    console.log(`Rendering cart item ${index + 1}:`, product.name);

    // Ensure price is a valid number
    const price = parseFloat(product.price) || 0;
    const quantity = parseInt(product.quantity) || 1;
    const itemTotal = price * quantity;
    subtotal += itemTotal;

    const li = document.createElement("li");
    li.className = "checkout-item";
    li.setAttribute(
      "aria-label",
      `${product.name}, quantity: ${quantity}, price: $${price.toFixed(2)}`
    );

    // Format the image if available
    let imageHtml = "";
    if (product.image) {
      imageHtml = `<img src="${product.image}" alt="${product.name}" style="width:30px;height:30px;margin-right:10px;border-radius:4px;">`;
    }

    li.innerHTML = `
      <span class="item-name">${imageHtml}${product.name}</span>
      <span class="item-price">$${price.toFixed(2)}</span>
      <span class="item-quantity">${quantity}</span>
      <span class="item-total">$${itemTotal.toFixed(2)}</span>
    `;

    checkOutList.appendChild(li);
  });

  // Calculate tax and total
  const tax = subtotal * 0.07; // 7% tax rate
  const total = subtotal + tax;

  // Update total displays
  subtotalElement.textContent = `$${subtotal.toFixed(2)}`;
  taxElement.textContent = `$${tax.toFixed(2)}`;
  totalElement.textContent = `$${total.toFixed(2)}`;

  // Store the total for order processing
  localStorage.setItem("orderTotal", total.toFixed(2));

  // Add interactive features to cart items - hover effects
  const cartItems = document.querySelectorAll(
    ".checkout-item:not(.empty-cart)"
  );
  cartItems.forEach((item) => {
    item.addEventListener("mouseenter", () => {
      item.style.backgroundColor = "#f0f4f8";
    });
    item.addEventListener("mouseleave", () => {
      item.style.backgroundColor = "";
    });
  });

  console.log(
    `Order summary updated - Subtotal: $${subtotal.toFixed(
      2
    )}, Total: $${total.toFixed(2)}`
  );

  // Return the total for other functions to use
  return total;
}

function calculateTotal() {
  let subtotal = 0;
  let cart = [];

  try {
    cart = JSON.parse(localStorage.getItem("cart")) || [];
  } catch (error) {
    console.error("Error parsing cart data:", error);
    return "0.00";
  }

  cart.forEach(function (product) {
    const price = parseFloat(product.price) || 0;
    const quantity = parseInt(product.quantity) || 1;
    subtotal += price * quantity;
  });

  const tax = subtotal * 0.07; // 7% tax
  const total = subtotal + tax;

  return total.toFixed(2);
}

let inputs = document.querySelectorAll(".inputs");
inputs.forEach((input) => {
  input.addEventListener("input", function () {
    if (this.value) {
      input.classList.add("inputLabel");
    } else {
      input.classList.remove("inputLabel");
    }
    // Clear field-specific error when user starts typing
    clearFieldError(this.id);
  });
});

// Function to display field-specific error messages
function showFieldError(fieldId, message) {
  // Get the field element
  const field = document.getElementById(fieldId);
  if (!field) return;

  // Add error class to highlight the field
  field.classList.add("field-error");

  // Check if error message element already exists
  let errorElement = document.getElementById(`${fieldId}-error`);

  // If error element doesn't exist, create it
  if (!errorElement) {
    errorElement = document.createElement("div");
    errorElement.id = `${fieldId}-error`;
    errorElement.className = "field-error-message";

    // Insert error message after the input field
    field.parentNode.insertBefore(errorElement, field.nextSibling);
  }

  // Set the error message
  errorElement.textContent = message;
  errorElement.style.display = "block";
}

// Function to clear field-specific error messages
function clearFieldError(fieldId) {
  // Get the field element
  const field = document.getElementById(fieldId);
  if (!field) return;

  // Remove error class
  field.classList.remove("field-error");

  // Hide error message if it exists
  const errorElement = document.getElementById(`${fieldId}-error`);
  if (errorElement) {
    errorElement.style.display = "none";
  }
}

// Create notification functions
function showSuccessNotification(
  message = "Your order has been placed successfully!",
  callback = null
) {
  console.log("Showing order confirmation notification...");

  // Get the notification element
  const notification = document.getElementById("success-notification");
  if (!notification) {
    console.error("Success notification element not found");
    if (callback) callback(); // Call callback immediately if notification doesn't exist
    return null;
  }

  // Clear any existing timeouts to prevent conflicts
  if (notification._showTimeout) clearTimeout(notification._showTimeout);
  if (notification._fadeTimeout) clearTimeout(notification._fadeTimeout);
  if (notification._callbackTimeout)
    clearTimeout(notification._callbackTimeout);
  if (notification._safetyTimeout) clearTimeout(notification._safetyTimeout);

  // Remove any hiding classes
  notification.classList.remove("hidden");
  notification.classList.remove("preload");

  // Get the message element and update it
  const messageElement = notification.querySelector(".notification-message");
  if (messageElement) {
    messageElement.textContent = message;
  }

  // Make notification more prominent with enhanced visibility
  notification.classList.add("prominent");

  // Reset any inline styles that might be conflicting
  notification.removeAttribute("style");

  // Set up initial styles
  notification.style.display = "flex";
  notification.style.visibility = "visible";
  notification.style.opacity = "0"; // Start transparent
  notification.style.transform = "translate(-50%, -50%) scale(0.9)"; // Start slightly smaller

  // Add show class
  notification.classList.add("show");

  // Store the callback for later execution
  if (typeof callback === "function") {
    notification._visibleCallback = callback;
  }

  // Constants for timing
  const displayDuration = 2000; // 2 seconds is enough for the success message
  const fadeOutDuration = 400;

  // Mark when notification became visible (for timing calculations)
  notification._visibleTimestamp = Date.now();

  // Set the proper styles with a brief delay to ensure the transition happens
  notification._showTimeout = setTimeout(() => {
    notification.style.opacity = "1";
    notification.style.transform = "translate(-50%, -50%) scale(1)";
    console.log("Notification should now be visible");
  }, 50);

  // Start fade out after display duration
  notification._fadeTimeout = setTimeout(() => {
    console.log("Starting notification fade out");
    // Start fade out animation
    notification.style.opacity = "0";
    notification.style.transform = "translate(-50%, -50%) scale(0.9)";

    // Wait for fade to complete, then execute callback
    notification._callbackTimeout = setTimeout(() => {
      notification.classList.remove("show");
      console.log("Order confirmation notification displayed and closed");

      // Only execute the callback if we haven't already done so
      if (
        notification._visibleCallback &&
        typeof notification._visibleCallback === "function"
      ) {
        console.log("Executing callback function after fade out");
        const callbackToRun = notification._visibleCallback;
        notification._visibleCallback = null; // Clear to prevent double execution

        // Calculate how long the notification was visible
        const visibleDuration =
          Date.now() - (notification._visibleTimestamp || Date.now());
        console.log(`Notification was visible for ${visibleDuration}ms`);

        // Ensure notification was visible for at least 1 second before redirect
        if (visibleDuration < 1000) {
          console.log("Adding small delay to ensure notification was visible");
          setTimeout(callbackToRun, 1000 - visibleDuration);
        } else {
          callbackToRun();
        }
      }
    }, fadeOutDuration);
  }, displayDuration);

  // Set a safety fallback in case the callback doesn't execute
  notification._safetyTimeout = setTimeout(() => {
    if (notification._visibleCallback) {
      console.log("Safety fallback: executing callback that did not run");
      const callbackToRun = notification._visibleCallback;
      notification._visibleCallback = null;
      callbackToRun();
    }
  }, displayDuration + fadeOutDuration + 1000); // Add 1 second safety margin

  // Return the notification element in case needed
  return notification;
}

// Function to safely redirect to confirmation page - simplified version
function redirectToConfirmation() {
  console.log("Redirecting to confirmation page...");

  try {
    // Ensure order completion flags are set
    sessionStorage.setItem("orderCompleted", "true");
    localStorage.setItem("orderCompletedFallback", "true");

    // Verify order data exists before redirecting
    const orderData =
      sessionStorage.getItem("orderData") || localStorage.getItem("orderData");

    if (!orderData) {
      console.warn("No order data found, creating minimal fallback");
      const fallbackData = {
        orderId: generateOrderId(),
        items: [],
        userDetails: { name: "Customer" },
        totalAmount: "0.00",
        orderDate: new Date().toISOString(),
        estimatedDelivery: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      };

      sessionStorage.setItem("orderData", JSON.stringify(fallbackData));
      localStorage.setItem("orderData", JSON.stringify(fallbackData));
    }

    // Show a brief message before redirect
    console.log("Navigation to confirmation page...");

    // Perform the actual redirect
    window.location.href = "../confirmation/confirm.html";
  } catch (error) {
    console.error("Error during redirect:", error);
    // Fallback redirect
    alert(
      "Your order was successful! Click OK to view your order confirmation."
    );
    window.location.href = "../confirmation/confirm.html";
  }
}

// Function to close any notification
function closeNotification(event) {
  const notification = this.closest(".notification");
  if (!notification) return;

  // Apply transition styles for smooth hiding
  notification.classList.remove("show");
  notification.style.opacity = "0";
  notification.style.visibility = "hidden";

  // Hide completely after transition
  setTimeout(() => {
    notification.style.display = "none";
  }, 300); // Match the transition duration

  // Prevent event bubbling
  event.stopPropagation();
}

// Improved error notification function
function showErrorNotification(
  message = "Please fix the errors in your form."
) {
  console.log("Showing error notification:", message);

  const notification = document.getElementById("error-notification");
  const messageElement = notification.querySelector(".notification-message");

  // Make notification more prominent
  notification.classList.add("prominent");

  if (messageElement) {
    messageElement.textContent = message;
  }

  // First set up the notification while hidden
  notification.style.opacity = "0";
  notification.style.visibility = "hidden";
  notification.style.display = "flex";

  // Make sure the close button has the correct event listener
  let closeButton = notification.querySelector(".notification-close");
  if (closeButton) {
    // Remove any existing listeners to prevent duplicates
    closeButton.removeEventListener("click", closeNotification);
    closeButton.addEventListener("click", closeNotification);
  } else {
    // Create close button if not present
    closeButton = document.createElement("button");
    closeButton.className = "notification-close";
    closeButton.setAttribute("aria-label", "Close notification");
    closeButton.innerHTML = '<i class="fas fa-times" aria-hidden="true"></i>';
    closeButton.addEventListener("click", closeNotification);
    notification.appendChild(closeButton);
  }

  // Trigger reflow to ensure transitions work properly
  void notification.offsetWidth;

  // Now make the notification visible with transition
  notification.classList.add("show");
  notification.style.visibility = "visible";
  notification.style.opacity = "1";
  notification.style.transform = "translateX(-50%) translateY(0)";

  // Automatically hide after a delay (only if not interacted with)
  const hideTimeout = setTimeout(() => {
    // Start fade out
    notification.classList.remove("show");
    notification.style.opacity = "0";
    notification.style.visibility = "hidden";

    // Complete hide after transition
    setTimeout(() => {
      notification.style.display = "none";

      // Also clear any pending timeouts associated with the notification
      if (notification._showTimeout) clearTimeout(notification._showTimeout);
      if (notification._fadeTimeout) clearTimeout(notification._fadeTimeout);
      if (notification._callbackTimeout)
        clearTimeout(notification._callbackTimeout);
      if (notification._safetyTimeout)
        clearTimeout(notification._safetyTimeout);
    }, 300);
  }, 8000);

  // Store the timeout ID on the notification element so it can be cleared if needed
  notification._hideTimeout = hideTimeout;

  return notification;
}

// Handle form submission with enhanced validation
document
  .getElementById("checkout-form")
  .addEventListener("submit", function (e) {
    e.preventDefault();

    // Clear all previous field errors
    document.querySelectorAll(".field-error").forEach((field) => {
      field.classList.remove("field-error");
    });
    document.querySelectorAll(".field-error-message").forEach((msg) => {
      msg.style.display = "none";
    });

    // Validate cart first
    let cart = [];
    try {
      cart = JSON.parse(localStorage.getItem("cart")) || [];
      if (!validateCart(cart)) {
        showErrorNotification(
          "Your cart is empty or contains invalid items. Please add items to your cart before checkout."
        );
        return false;
      }
    } catch (error) {
      console.error("Error validating cart:", error);
      showErrorNotification(
        "There was a problem with your cart. Please try again."
      );
      return false;
    }

    const signInUser = document.getElementById("signInUsername").value;
    const signInEmail = document.getElementById("signInEmail").value;
    const phoneInput = document.getElementById("phoneNumber");
    const addressInput = document.getElementById("address");
    const cityInput = document.getElementById("city");
    const countryInput = document.getElementById("country");

    // Track validation errors
    let validationErrors = [];

    // Validate each field and collect errors
    const isFullNameValid = validateFullName(signInUser);
    if (!isFullNameValid) validationErrors.push("Full Name");

    const isEmailValid = validateInEmail(signInEmail);
    if (!isEmailValid) validationErrors.push("Email");

    const isPhoneValid = validatePhoneNumber();
    if (!isPhoneValid) validationErrors.push("Phone Number");

    const isAddressValid = validateAddress(addressInput.value);
    if (!isAddressValid) validationErrors.push("Address");

    const isCityValid = validateCity(cityInput.value);
    if (!isCityValid) validationErrors.push("City");

    const isCountryValid = validateCountry(countryInput.value);
    if (!isCountryValid) validationErrors.push("Country");

    // Check if a payment method is selected
    const paymentMethods = document.querySelectorAll(".payment-method");
    let paymentMethodSelected = false;
    paymentMethods.forEach((method) => {
      if (method.getAttribute("aria-checked") === "true") {
        paymentMethodSelected = true;
      }
    });

    if (!paymentMethodSelected) {
      validationErrors.push("Payment Method");
      showErrorNotification(
        "Please select a payment method before placing your order."
      );
      return false;
    }

    // If there are validation errors, show a specific error message
    if (validationErrors.length > 0) {
      showErrorNotification(
        `Please correct issues with: ${validationErrors.join(", ")}`
      );
      return false;
    }

    // If all validations pass
    if (
      isFullNameValid &&
      isEmailValid &&
      isPhoneValid &&
      isAddressValid &&
      isCityValid &&
      isCountryValid
    ) {
      // Show enhanced loading state with informative text
      const placeOrderBtn = document.getElementById("placeOrderBtn");
      placeOrderBtn.classList.add("loading");
      placeOrderBtn.disabled = true;
      placeOrderBtn.innerHTML =
        '<i class="fas fa-spinner fa-spin"></i> Processing Order...';

      // Add a visual processing indicator to the form
      const form = document.getElementById("checkout-form");
      const processingIndicator = document.createElement("div");
      processingIndicator.className = "processing-indicator";
      processingIndicator.innerHTML =
        '<div class="processing-spinner"></div><p>Processing your order, please wait...</p>';
      form.appendChild(processingIndicator);

      console.log("Processing order...");

      // Simulate order processing (would be an API call in a real app)
      // Save form data before any asynchronous operations
      const userData = {
        name: signInUser,
        email: signInEmail,
        phone: phoneInput.value,
        address: addressInput.value,
        city: cityInput.value,
        country: countryInput.value,
      };

      // Store user data immediately to prevent loss
      localStorage.setItem("checkoutUserData", JSON.stringify(userData));

      console.log("Processing and storing order details...");

      try {
        // Pass values and store order details
        const fullAddress = storeUserDetails();

        // Prepare order items for storage
        const totalAmount =
          localStorage.getItem("orderTotal") || calculateTotal();
        console.log("Order total amount:", totalAmount);

        // Store order details for confirmation page
        const orderData = storeOrderData(
          cart,
          {
            name: signInUser,
            email: signInEmail,
            phone: phoneInput.value,
            address: fullAddress,
          },
          totalAmount
        );

        console.log(
          "Order data stored successfully:",
          orderData?.orderId || "Unknown ID"
        );

        // Mark order as completed to enable confirmation step
        sessionStorage.setItem("orderCompleted", "true");
        localStorage.setItem("orderCompletedFallback", "true");
        console.log("Order completion status saved successfully");

        // Enable confirmation step
        enableConfirmationStep();

        // Update button state with enhanced success indication
        placeOrderBtn.classList.remove("loading");
        placeOrderBtn.classList.add("success");
        placeOrderBtn.innerHTML =
          '<i class="fas fa-check"></i> Order Placed Successfully!';

        // Remove the processing indicator
        const processingIndicator = document.querySelector(
          ".processing-indicator"
        );
        if (processingIndicator) {
          processingIndicator.remove();
        }

        // Clear cart after successful order
        localStorage.removeItem("cart");

        // Store selected payment method for confirmation page
        const selectedPayment = document.querySelector(
          '.payment-method[aria-checked="true"]'
        );
        if (selectedPayment) {
          const paymentMethod =
            selectedPayment.getAttribute("data-payment-method") ||
            selectedPayment.textContent.trim();
          sessionStorage.setItem("selectedPaymentMethod", paymentMethod);
          localStorage.setItem("selectedPaymentMethod", paymentMethod); // Backup storage
          console.log("Stored payment method:", paymentMethod);
        }

        console.log(
          "Order placed successfully, showing notification and redirecting..."
        );

        // Show success notification with direct redirect callback
        showSuccessNotification(
          "Order placed successfully! Redirecting to confirmation page...",
          function () {
            console.log("Success notification completed, preparing redirect");

            // Ensure we have all order data before redirect
            const orderData =
              sessionStorage.getItem("orderData") ||
              localStorage.getItem("orderData");
            if (!orderData) {
              console.warn("Order data missing before redirect");
              // Regenerate if missing
              storeOrderData(
                cart,
                {
                  name: signInUser,
                  email: signInEmail,
                  phone: phoneInput.value,
                  address: fullAddress,
                },
                totalAmount
              );
            }

            // Set completion flags again to be safe
            sessionStorage.setItem("orderCompleted", "true");
            localStorage.setItem("orderCompletedFallback", "true");

            // Store selected payment method before redirect
            const selectedPayment = document.querySelector(
              '.payment-method[aria-checked="true"]'
            );
            if (selectedPayment) {
              const paymentMethod =
                selectedPayment.getAttribute("data-payment-method") ||
                selectedPayment.textContent.trim();
              sessionStorage.setItem("selectedPaymentMethod", paymentMethod);
            }

            // Add a tiny delay before redirect for better user experience
            setTimeout(function () {
              // Execute redirect directly
              console.log("Executing final redirect to confirmation page");
              window.location.href = "../confirmation/confirm.html";
            }, 100);
          }
        );
      } catch (error) {
        console.error("Error processing order:", error);

        // Reset button state
        placeOrderBtn.classList.remove("loading");
        placeOrderBtn.disabled = false;
        placeOrderBtn.innerHTML = "Place Order";

        // Remove processing indicator if present
        const processingIndicator = document.querySelector(
          ".processing-indicator"
        );
        if (processingIndicator) {
          processingIndicator.remove();
        }

        showErrorNotification(
          "There was a problem processing your order. Please try again."
        );
      }
    }
  });

// Listen for storage events to help debug issues
window.addEventListener("storage", function (e) {
  console.log(
    "Storage changed:",
    e.key,
    "Old value:",
    e.oldValue,
    "New value:",
    e.newValue
  );
});
function validateInEmail(signInEmail) {
  const check_signInEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!check_signInEmail.test(signInEmail)) {
    showFieldError("signInEmail", "Email must contain @ before domain name");
    return false;
  }
  return true;
}

function validateFullName(fullName) {
  // Remove extra spaces and trim
  const trimmedName = fullName.trim().replace(/\s+/g, " ");

  // Split the name into parts
  const nameParts = trimmedName.split(" ");

  // Check if empty or only spaces
  if (!trimmedName) {
    showFieldError(
      "signInUsername",
      "Please enter your full name (first and last name)"
    );
    return false;
  }

  // Check if we have at least first and last name
  if (nameParts.length < 2) {
    showFieldError(
      "signInUsername",
      "Please enter both your first and last name, separated by a space"
    );
    return false;
  }

  // Check each name part
  for (const part of nameParts) {
    // Check minimum length for each part
    if (part.length < 2) {
      showFieldError(
        "signInUsername",
        `The name "${part}" is too short. Each name must be at least 2 characters long`
      );
      return false;
    }

    // Check if part contains only valid characters
    // Allow letters, accented characters, hyphens, and apostrophes
    if (
      !/^[A-Za-zÀ-ÿ](?:[A-Za-zÀ-ÿ]|-(?=[A-Za-zÀ-ÿ])|'(?=[A-Za-zÀ-ÿ]))*[A-Za-zÀ-ÿ]$/.test(
        part
      )
    ) {
      showFieldError(
        "signInUsername",
        "Names can only contain letters, hyphens (-), and apostrophes ('). " +
          "Numbers and other special characters are not allowed"
      );
      return false;
    }
  }

  // Clear any existing error when validation passes
  clearFieldError("signInUsername");
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
    showFieldError(
      "phoneNumber",
      "Please enter a valid phone number with at least 10 digits"
    );
    return false;
  }
  return true;
}
function validateAddress(address) {
  if (address.trim() === "") {
    showFieldError("address", "Please enter your address");
    return false;
  }
  return true;
}

function validateCity(city) {
  if (city.trim() === "") {
    showFieldError("city", "Please enter your city");
    return false;
  }
  return true;
}

function validateCountry(country) {
  if (country.trim() === "") {
    showFieldError("country", "Please enter your country");
    return false;
  }
  return true;
}

// Add CSS for field-specific error styling
document.addEventListener("DOMContentLoaded", function () {
  // Create style element for field error styling if it doesn't exist
  if (!document.getElementById("field-error-styles")) {
    const styleElement = document.createElement("style");
    styleElement.id = "field-error-styles";
    styleElement.textContent = `
      /* Tooltip styles */
      .tooltip {
        position: relative;
        display: inline-block;
      }
      
      /* Additional styles for disabled confirmation step */
      .disabled {
        pointer-events: none;
        opacity: 0.6;
        cursor: not-allowed;
      }
      
      .disabled:hover .tooltip-text {
        visibility: visible;
        opacity: 1;
      }
      
      .tooltip .tooltip-text {
        visibility: hidden;
        width: 220px;
        background-color: #ff6b6b !important;
        color: white !important;
        font-weight: bold !important;
        text-align: center;
        border-radius: 6px;
        padding: 5px;
        position: absolute;
        z-index: 10;
        bottom: 125%;
        left: 50%;
        transform: translateX(-50%);
        opacity: 0;
        transition: opacity 0.3s;
        font-size: 14px;
        pointer-events: none;
      }
      
      .tooltip .tooltip-text::after {
        content: "";
        position: absolute;
        top: 100%;
        left: 50%;
        margin-left: -5px;
        border-width: 5px;
        border-style: solid;
        border-color: #ff6b6b transparent transparent transparent;
      }
      
      .tooltip:hover .tooltip-text {
        visibility: visible;
        opacity: 1;
      }
      .field-error {
        border: 2px solid #ff3333 !important;
        background-color: #fff8f8 !important;
      }
      .field-error-message {
        color: #ff3333;
        font-size: 14px;
        margin-top: 5px;
        padding-left: 10px;
      }
      .checkout-item {
        display: grid;
        grid-template-columns: 2fr 1fr 1fr 1fr;
        gap: 1rem;
        padding: 1rem;
        border-bottom: 1px solid #e2e8f0;
        align-items: center;
        width: 100%;
        background: white;
        z-index: 3;
      }
      .item-name {
        display: flex;
        align-items: center;
        gap: 10px;
        font-weight: 500;
        color: #2d3748;
      }
      .item-price, .item-quantity, .item-total {
        text-align: right;
        font-weight: 500;
        color: #2d3748;
      }
      .item-total {
        font-weight: 600;
        color: #3a6ea5;
      }
      .checkout-item:hover {
        background-color: #f7fafc;
      }
      .checkout-item.empty-cart {
        grid-template-columns: 1fr;
        text-align: center;
        color: #718096;
        padding: 2rem;
        font-style: italic;
      }
      .checkout-item.empty-cart .item-name {
        text-align: center;
        font-weight: normal;
      }
    `;
    document.head.appendChild(styleElement);
  }

  // Also add styles specific to the order summary
  if (!document.getElementById("order-summary-styles")) {
    const orderSummaryStyles = document.createElement("style");
    orderSummaryStyles.id = "order-summary-styles";
    orderSummaryStyles.textContent = `
      .order-summary {
        margin-bottom: 2rem;
        width: 100%;
        max-width: 800px;
        background-color: white;
        border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
        overflow: hidden;
        position: relative;
        z-index: 2;
      }
      .cart-summary-headers {
        font-weight: 600;
        background-color: #f0f4f8;
        color: #2d3748;
      }
      .checkout-totals {
        padding: 1rem;
        border-top: 2px solid #f0f4f8;
      }
      .subtotal, .tax, .total {
        display: flex;
        justify-content: space-between;
        padding: 0.5rem 0;
      }
      .total {
        font-weight: bold;
        border-top: 1px solid #e2e8f0;
        margin-top: 0.5rem;
        padding-top: 1rem;
        color: #3a6ea5;
      }
    `;
    document.head.appendChild(orderSummaryStyles);
  }
});

// Add an event listener to manually test the success notification and redirect
// for debugging purposes - can be removed in production
document.addEventListener("keydown", function (e) {
  // Press Ctrl+Shift+S to manually test the success flow
  if (e.ctrlKey && e.shiftKey && e.key === "S") {
    e.preventDefault();
    console.log("Testing success notification and redirect flow");

    const cart = JSON.parse(localStorage.getItem("cart") || "[]");
    const totalAmount = localStorage.getItem("orderTotal") || calculateTotal();

    // Store dummy order data
    storeOrderData(
      cart,
      {
        name: "Test User",
        email: "test@example.com",
        phone: "1234567890",
        address: "Test Address, Test City, Test Country",
      },
      totalAmount
    );

    // Mark order as completed
    sessionStorage.setItem("orderCompleted", "true");
    localStorage.setItem("orderCompletedFallback", "true");

    // Show success notification and redirect
    showSuccessNotification(
      "Test order placed successfully! Redirecting to confirmation page...",
      function () {
        redirectToConfirmation();
      }
    );
  }
});

// Enhance the card number formatting with validation feedback
document.addEventListener("DOMContentLoaded", function () {
  const cardNumberInput = document.getElementById("numberInput");
  if (cardNumberInput) {
    const errorElement = document.getElementById("card-number-error");

    function validateCardNumber(value) {
      // Remove spaces for validation
      const cardNumber = value.replace(/\s/g, "");
      return {
        isValid: /^\d{16}$/.test(cardNumber),
        isComplete: cardNumber.length === 16,
        isTooLong: cardNumber.length > 16,
      };
    }

    cardNumberInput.addEventListener("input", function (e) {
      // Remove all non-digit characters
      let value = this.value.replace(/\D/g, "");

      // Add a space after every 4 digits
      let formattedValue = value.replace(/(\d{4})(?=\d)/g, "$1 ");

      // Limit the total length to 19 characters (16 digits + 3 spaces)
      formattedValue = formattedValue.substring(0, 19);

      // Update the input value
      this.value = formattedValue;

      // Validate and show feedback
      const validation = validateCardNumber(formattedValue);

      if (formattedValue.length > 0) {
        if (validation.isTooLong) {
          errorElement.textContent =
            "Card number cannot be longer than 16 digits";
          errorElement.style.display = "block";
          this.classList.add("field-error");
        } else if (validation.isComplete && !validation.isValid) {
          errorElement.textContent =
            "Please enter a valid 16-digit card number";
          errorElement.style.display = "block";
          this.classList.add("field-error");
        } else if (!validation.isComplete) {
          errorElement.textContent = `Please enter all 16 digits (${value.length}/16)`;
          errorElement.style.display = "block";
          this.classList.remove("field-error");
        } else {
          errorElement.style.display = "none";
          this.classList.remove("field-error");
        }
      } else {
        errorElement.style.display = "none";
        this.classList.remove("field-error");
      }

      // Move cursor to end if user is typing
      if (document.activeElement === this) {
        const end = this.value.length;
        this.setSelectionRange(end, end);
      }
    });

    // Add keydown event to prevent cursor jumping and handle backspace
    cardNumberInput.addEventListener("keydown", function (e) {
      if (
        e.key === "Backspace" &&
        this.value.charAt(this.value.length - 1) === " "
      ) {
        this.value = this.value.slice(0, -2);
        e.preventDefault();
      }
    });

    // Add blur event to show error only after user leaves the field
    cardNumberInput.addEventListener("blur", function () {
      const validation = validateCardNumber(this.value);
      if (this.value.length > 0 && !validation.isComplete) {
        errorElement.textContent =
          "Please enter all 16 digits of your card number";
        errorElement.style.display = "block";
        this.classList.add("field-error");
      }
    });

    // Add focus event to provide immediate feedback
    cardNumberInput.addEventListener("focus", function () {
      if (this.value.length === 0) {
        errorElement.textContent = "Enter your 16-digit card number";
        errorElement.style.display = "block";
        this.classList.remove("field-error");
      }
    });
  }
});
