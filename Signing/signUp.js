let loggedIn = false;
let signupBtn = document.getElementById("submitSignUp");
let users = JSON.parse(localStorage.getItem("users")) || []; // Load users from local storage

//Function to pre-fill the sign-up form if the user data exists

function preFillForm() {
  document
    .getElementById("signUpUsername")
    .addEventListener("focus", function () {
      if (users.length > 0 && this.value === "") {
        this.value = users[0].Username;
      }
    });
  document.getElementById("signUpEmail").addEventListener("focus", function () {
    if (users.length > 0 && this.value === "") {
      this.value = users[0].Email;
    }
  });
}

signupBtn.addEventListener("click", function (event) {
  event.preventDefault();

  let signupUsername = document.getElementById("signUpUsername").value;
  let signupEmail = document.getElementById("signUpEmail").value;
  let signupPassword = document.getElementById("signUpPassword").value;

  // Check if user already exists
  const userExists = users.some(
    (user) => user.Username === signupUsername || user.Email === signupEmail,
  );
  if (userExists) {
    alert("User already exists with this username or email! Sign in");
    // Clear the input fields when user already exists
    document.getElementById("signUpUsername").value = "";
    document.getElementById("signUpPassword").value = "";
    document.getElementById("signUpEmail").value = "";
    return;
  }

  if (
    validateupUsername(signupUsername) &&
    validateupEmail(signupEmail) &&
    validateupPassword(signupPassword)
  ) {
    alert(
      `Account created successfully, ${signupUsername}, Now Sign in to Explore our site`,
    );
    loggedIn = true;
    users.push({
      Username: signupUsername,
      Email: signupEmail,
      Password: signupPassword,
    });
    localStorage.setItem("users", JSON.stringify(users)); // Save users to local storage.

    // Clear the input fields after successful sign-up for security purposes and reducing confusion
    document.getElementById("signUpUsername").value = "";
    document.getElementById("signUpPassword").value = "";
    document.getElementById("signUpEmail").value = "";
  } else {
    alert("Wrong credentials or user already exists!!");
    loggedIn = false;
  }
});

//Call the pre-fill function o page load, this allows to sign in without manually entering the credentials, inshort is (autofill).

preFillForm();

function validateupUsername(signupUsername) {
  const check_signupUsername = /^[A-Z][a-zA-Z0-9]{5,}$/;
  if (!check_signupUsername.test(signupUsername)) {
    alert(
      "Username must start with a capital and not be less than 5 characters",
    );
    return false;
  }
  return true;
}

function validateupEmail(signupEmail) {
  const check_signupEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!check_signupEmail.test(signupEmail)) {
    alert("Email must contain @ before domain name");
    return false;
  }
  return true;
}

function validateupPassword(signupPassword) {
  const check_signupPassword =
    /^(?=.*[!@#$%^&*])(?=.*\d)(?=.*[A-Z])(?=.*[a-z]).{8,}$/;
  if (!check_signupPassword.test(signupPassword)) {
    alert(
      "Password must be more than 8 characters, contain a capital and a small letter, and a special character",
    );
    return false;
  }
  return true;
}
