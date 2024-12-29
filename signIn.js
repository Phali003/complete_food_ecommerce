document.addEventListener("DOMContentLoaded", function() {
    let loggedIn = false;
    let signinBtn = document.getElementById("submitSignIn");

    signinBtn.addEventListener("click", function(event) {
        event.preventDefault();

        let signinUsername = document.getElementById("signInUsername").value;
        let signinPassword = document.getElementById("signInPassword").value;

        // Check if user exists in localStorage
        let storedUser = JSON.parse(localStorage.getItem('user'));

        if (!storedUser) {
            alert("User does not exist. Please sign up first.");
            return; // Exit the function if user does not exist
        }

        // Validate username and password
        if (validateUsername(signinUsername) && validatePassword(signinPassword)) {
            if (storedUser.username === signinUsername) {
                if (storedUser.password === signinPassword) {
                    alert(`Logged in successfully, ${signinUsername}`);
                    loggedIn = true;

                    // Redirect to another page
                    window.location.href = "menu.html";
                } else {
                    alert("Wrong password, try again!!");
                    loggedIn = false;
                }
            } else {
                alert("Wrong username, try again!!");
                loggedIn = false;
            }
        }
    });

    function validateUsername(signinUsername) {
        const check_signinUsername = /^[A-Z][a-zA-Z0-9]{5,}$/;
        if (!check_signinUsername.test(signinUsername)) {
            alert("Username must start with a capital letter and not be less than 5 characters");
            return false; 
        }
        return true; 
    }

    function validatePassword(signinPassword) {
        const check_signinPassword = /^(?=.*[!@#$%^&*])(?=.*\d)(?=.*[A-Z])(?=.*[a-z]).{8,}$/;
        if (!check_signinPassword.test(signinPassword)) {
            alert("Password must be more than 8 characters, contain a capital letter, a small letter, and a special character");
            return false; 
        }
        return true;
    }
});
