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