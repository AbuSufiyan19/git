document.addEventListener("DOMContentLoaded", function () {
    const passwordField = document.getElementById("password");
    const confirmPasswordField = document.getElementById("confirmPassword");
    const errorMessage = document.querySelector(".error-message");
  
    confirmPasswordField.addEventListener("input", function () {
      if (passwordField.value !== confirmPasswordField.value) {
        errorMessage.style.display = "block";
      } else {
        errorMessage.style.display = "none";
      }
    });
    });
  
    document.addEventListener("DOMContentLoaded", function () {
      const emailField = document.getElementById("email");
      const emailError = document.getElementById("email-error");
    
      emailField.addEventListener("input", function () {
        const email = emailField.value;
        const isValid = isEmailValid(email);
    
        if (isValid) {
          emailError.textContent = "";
          emailField.classList.remove("invalid");
        } else {
          emailError.textContent = "Invalid email address";
          emailField.classList.add("invalid");
        }
      });
    
      function isEmailValid(email) {
        // A simple regular expression to check for a valid email format
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return emailPattern.test(email);
      }
    });
    
    document.addEventListener("DOMContentLoaded", function () {
      const passwordField = document.getElementById("password");
      const passwordError = document.getElementById("password-error");
    
      passwordField.addEventListener("input", function () {
        const password = passwordField.value;
        const isValid = isPasswordValid(password);
    
        if (isValid) {
          passwordError.textContent = "";
          passwordField.classList.remove("invalid");
        } else {
          passwordError.textContent = "Password should be at least 8 characters long and contain at least one letter and one number";
          passwordField.classList.add("invalid");
        }
      });
    
      function isPasswordValid(password) {
        // Password should be at least 8 characters long and contain at least one letter and one number
        const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/; 
        return passwordPattern.test(password);
      }
    });
    