# Insecure Default Variable Initialization in Rust 🦀

A practical demonstration of the insecure default variable initialization vulnerability using a Rust web application built with the actix-web framework.

## 📚 Lesson Summary

**Insecure default variable initialization** is a security vulnerability where variables are initialized with unsafe default values. This is particularly dangerous for security-sensitive settings like cookie configurations.

When security attributes such as `secure`, `httpOnly`, or `sameSite` are not explicitly set to secure values, they often default to insecure settings, creating significant security risks.

### 🔍 What This Demo Shows

This application demonstrates the vulnerability through two login endpoints:

- **`/vulnerable/login`** - Sets cookies using default, insecure settings
- **`/secure/login`** - Explicitly configures cookies with secure attributes

### ⚠️ Security Impact

- **Missing Secure flag**: Cookies can be intercepted in Man-in-the-Middle (MITM) attacks
- **Missing HttpOnly flag**: Cookies can be stolen via Cross-Site Scripting (XSS), leading to session hijacking
- **Missing SameSite attribute**: Cookies may be sent on cross-site requests, enabling CSRF attacks

## 🚀 Application Setup and Execution

Follow these steps to set up and run the demonstration application.

### 📋 Prerequisites

- Rust toolchain (rustc and cargo) installed

### 🔧 Step-by-Step Instructions

1. **Clone the Repository / Create the Files**

   ```bash
   git clone <repository-url>
   cd insecure_default_variable_initialization
   ```

2. **Build the Application**

   ```bash
   cargo build
   ```

3. **Run the Application**

   ```bash
   cargo run
   ```

   You should see the output: `Server running at http://127.0.0.1:8080`

## 🔍 Demonstrating the Vulnerability

We will use `curl` with the `-v` (verbose) flag to inspect the `Set-Cookie` headers returned by the server.

### 🚨 Vulnerable Endpoint

Send a POST request to the `/vulnerable/login` endpoint:

```bash
curl -v -X POST http://127.0.0.1:8080/vulnerable/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

#### 📊 Analyze the Output

Look for the `Set-Cookie` headers in the verbose output (lines starting with `< Set-Cookie`):

```
< Set-Cookie: auth=auth_token_for_admin
< Set-Cookie: tracking=tracker_id_for_admin
```

#### 🔓 Vulnerability Analysis

- **Missing Secure flag**: The cookie can be sent over unencrypted HTTP
- **Missing HttpOnly flag**: The cookie can be accessed by client-side JavaScript (XSS vulnerable)
- **Missing SameSite attribute**: Browser defaults to Lax, which is better than nothing but not as secure as Strict for authentication cookies

## 🔒 Demonstrating the Mitigation

Now, we will interact with the secure endpoint and compare the results.

### 🛡️ Secure Endpoint

Send a POST request to the `/secure/login` endpoint:

```bash
curl -v -X POST http://127.0.0.1:8080/secure/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

#### 📊 Analyze the Output

Again, inspect the `Set-Cookie` headers. This time, they will be very different:

```
< Set-Cookie: auth=auth_token_for_admin; path=/; expires=...; secure; HttpOnly; SameSite=Strict
< Set-Cookie: tracking=tracker_id_for_admin; path=/; expires=...; secure
```

_(Note: The expires value will vary)_

#### ✅ Mitigation Analysis

By explicitly initializing the cookie attributes, we have fixed the vulnerabilities:

- **`secure`**: The cookie will now only be sent over secure HTTPS connections
- **`HttpOnly`**: The cookie is now inaccessible to client-side scripts, protecting it from XSS-based theft
- **`SameSite=Strict`**: The cookie will not be sent on cross-site requests, protecting against CSRF attacks

## 🎯 Key Takeaways

This exercise demonstrates the **critical importance** of never relying on default values for security-sensitive configurations. Always explicitly define them to ensure your application remains secure.

### 📝 Best Practices

1. **Never trust default values** for security-related configurations
2. **Always explicitly set** cookie security attributes
3. **Use the most restrictive settings** that still allow your application to function
4. **Test your configurations** to verify they work as expected

### 🔧 Additional Resources

- [OWASP - Secure Cookie Attributes](https://owasp.org/www-community/controls/SecureCookieAttribute)
- [MDN - HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [actix-web Cookie Documentation](https://docs.rs/actix-web/latest/actix_web/cookie/index.html)
