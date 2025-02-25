document.addEventListener("DOMContentLoaded", function () {
  let loggedIn = false;
  let signinBtn = document.getElementById("submitSignIn");

  signinBtn.addEventListener("click", function (event) {
    event.preventDefault();

    let signinUsername = document.getElementById("signInUsername").value;
    let signinPassword = document.getElementById("signInPassword").value;

    // Check if users exist in localStorage
    let storedUsers = JSON.parse(localStorage.getItem("users")) || [];

    if (storedUsers.length === 0) {
      alert("User does not exist. Please sign up first.");
      return; // Exit the function if no users exist
    }

    // Validate username and password
    if (validateUsername(signinUsername) && validatePassword(signinPassword)) {
      // Check if the user exists in the stored users array
      const user = storedUsers.find(
        (user) =>
          user.Username === signinUsername && user.Password === signinPassword,
      );

      if (user) {
        alert(`Logged in successfully, ${signinUsername}`);
        loggedIn = true;
        // Clear the input fields after successful sign-in for security purposes and reducing confusion
        document.getElementById("signUpUsername").value = "";
        document.getElementById("signUpPassword").value = "";

        // Redirect to another page
        window.location.href = "index.html";
      } else {
        alert("Wrong username or password, try again!!");
        loggedIn = false;
      }
    }
  });

  function validateUsername(signinUsername) {
    const check_signinUsername = /^[A-Z][a-zA-Z0-9]{5,}$/;
    if (!check_signinUsername.test(signinUsername)) {
      alert(
        "Username must start with a capital letter and not be less than 5 characters",
      );
      return false;
    }
    return true;
  }

  function validatePassword(signinPassword) {
    const check_signinPassword =
      /^(?=.*[!@#$%^&*])(?=.*\d)(?=.*[A-Z])(?=.*[a-z]).{8,}$/;
    if (!check_signinPassword.test(signinPassword)) {
      alert(
        "Password must be more than 8 characters, contain a capital letter, a small letter, and a special character",
      );
      return false;
    }
    return true;
  }
});
