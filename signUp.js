let loggedIn = false;
let signupBtn = document.getElementById("submitSignUp");
let users = JSON.parse(localStorage.getItem('users')) || []; // Load users from local storage

signupBtn.addEventListener("click", function(event){
    event.preventDefault();

    let signupUsername = document.getElementById("signUpUsername").value;
    let signupEmail = document.getElementById("signUpEmail").value;
    let signupPassword = document.getElementById("signUpPassword").value;

    // Check if user already exists
    const userExists = users.some(user => user.Username === signupUsername || user.Email === signupEmail);
    if(userExists){
        alert("User already exists with this username or email! Sign in");
        return;
    }
    
    if(validateupUsername(signupUsername) && validateupEmail(signupEmail) && validateupPassword(signupPassword)){
        alert(`Account created successfully, ${signupUsername}`);
        loggedIn = true;
        users.push({Username: signupUsername, Email: signupEmail, Password: signupPassword});
        localStorage.setItem('users', JSON.stringify(users)); // Save users to local storage
        // window.location.href="SignIn.html";
    }
    else{
        alert("Wrong credentials or user already exists!!");
        loggedIn = false;
    }
});
  
function validateupUsername(signupUsername){
    const check_signupUsername = /^[A-Z][a-zA-Z0-9]{5,}$/;
    if(!check_signupUsername.test(signupUsername)){
        alert("Username must start with a capital and not be less than 5 characters");
        return false; 
    }
    return true; 
}

function validateupEmail(signupEmail){
    const check_signupEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if(!check_signupEmail.test(signupEmail)){
        alert("Email must contain @ before domain name");
        return false;
    }
    return true;
}

function validateupPassword(signupPassword){
    const check_signupPassword = /^(?=.*[!@#$%^&*])(?=.*\d)(?=.*[A-Z])(?=.*[a-z]).{8,}$/;
    if(!check_signupPassword.test(signupPassword)){
        alert("Password must be more than 8 characters, contain a capital and a small letter, and a special character");
        return false;
    }
    return true;
}  
