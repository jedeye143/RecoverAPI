# RecoverPH API Endpoints

This document provides an overview of the available API endpoints for the **RecoverPH API**, built with ASP.NET Core 8.

---

## Goal

To provide a clear reference for authentication, user management, and profile-related API endpoints.

Current API base:

const API_BASE = "https://localhost:7164";
---

## Endpoints

### Authentication

**POST**  
`/register`  
Registers a new user account.  

**POST**  
`/login`  
Logs in a user and returns a JWT.  

**POST**  
`/refresh`  
Refreshes the JWT using a refresh token.  

---

### Email Confirmation

**GET**  
`/confirmEmail`  
Confirms a user’s email address via token.  

**POST**  
`/resendConfirmationEmail`  
Resends the email confirmation link.  

---

### Password Reset

**POST**  
`/forgotPassword`  
Initiates password reset and sends reset link to email.  

**POST**  
`/resetPassword`  
Resets password using reset token.  

---

### Two-Factor Authentication

**POST**  
`/manage/2fa`  
Enables or disables 2FA for the user.  

---

### Profile Management

**GET**  
`/manage/info`  
Gets the user’s profile information.  

**POST**  
`/manage/info`  
Updates the user’s profile information.  
