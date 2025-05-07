# NetworkSecurity
This project demonstrates essential security practices in web applications, including:

- **JWT Authentication**  
  Secure login with JSON Web Tokens.

- **Authorization**  
  Role-based access control to protect protected endpoints.

- **AES Encryption & Decryption**  
  Sensitive data is encrypted and decrypted using the AES algorithm.

- **Hashing with BCrypt**  
  Passwords are securely hashed using the BCrypt algorithm to ensure they are not stored in plain text.

- **Refresh Token System**  
  Access tokens can be renewed using refresh tokens. Once a refresh token is revoked, the user must log in again.

---

## Unauthorized and Forbidden Access

The application provides clear feedback when access is denied due to authentication or authorization failures.

### Unauthorized Access
![Unauthorized Error](Network%20Security/Images/unauthorized.png)

### Forbidden Access
![Forbidden Error](Network%20Security/Images/forbidden.png)

