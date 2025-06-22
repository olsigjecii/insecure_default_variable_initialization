Lesson: Insecure Default Variable Initialization in Rust
1. Lesson Summary
This lesson explores the Insecure Default Variable Initialization vulnerability within the context of a Rust web application built with the actix-web framework.

Insecure default variable initialization is a security oversight where variables are initialized with unsafe default values. This is particularly dangerous for security-sensitive settings. In web development, a common example is cookie configuration. If security attributes like secure, httpOnly, or sameSite are not explicitly set to true or a strict value, they often default to insecure settings.

This application demonstrates this vulnerability by providing two login endpoints:

A /vulnerable/login endpoint that sets cookies using the default, insecure settings.
A /secure/login endpoint that explicitly configures cookies with secure attributes, mitigating the risks.
The impact of such insecure defaults can be severe. A cookie without the secure flag can be intercepted in a Man-in-the-Middle (MITM) attack. A cookie without the httpOnly flag can be stolen via Cross-Site Scripting (XSS), potentially leading to session hijacking.

2. Application Setup and Execution
Follow these steps to set up and run the demonstration application.

Prerequisites
Rust toolchain (rustc and cargo) installed.
Step-by-Step Instructions
Clone the Repository / Create the Files:
Save the code above into the file structure described (Cargo.toml and src/main.rs).

Build the Application:
Navigate to the project's root directory and run the build command:

Bash

cargo build
Run the Application:
Start the server with the following command:

Bash

cargo run
You should see the output: Server running at http://127.0.0.1:8080

3. Demonstrating the Vulnerability
We will use curl with the -v (verbose) flag to inspect the Set-Cookie headers returned by the server.

Vulnerable Endpoint
Send a POST request to the /vulnerable/login endpoint:

Bash

curl -v -X POST http://127.0.0.1:8080/vulnerable/login \
-H "Content-Type: application/json" \
-d '{"username": "admin", "password": "password"}'
Analyze the Output:
Look for the Set-Cookie headers in the verbose output (lines starting with < Set-Cookie). You will see something like this:

< Set-Cookie: auth=auth_token_for_admin
< Set-Cookie: tracking=tracker_id_for_admin
Vulnerability Analysis:

Missing Secure flag: The cookie can be sent over unencrypted HTTP.
Missing HttpOnly flag: The cookie can be accessed by client-side JavaScript, making it vulnerable to XSS attacks.
Missing SameSite attribute: The browser will default to Lax, which is better than nothing but not as secure as Strict for a sensitive authentication cookie.
4. Demonstrating the Mitigation
Now, we will interact with the secure endpoint and compare the results.

Secure Endpoint
Send a POST request to the /secure/login endpoint:

Bash

curl -v -X POST http://127.0.0.1:8080/secure/login \
-H "Content-Type: application/json" \
-d '{"username": "admin", "password": "password"}'
Analyze the Output:
Again, inspect the Set-Cookie headers. This time, they will be very different:

< Set-Cookie: auth=auth_token_for_admin; path=/; expires=...; secure; HttpOnly; SameSite=Strict
< Set-Cookie: tracking=tracker_id_for_admin; path=/; expires=...; secure
(Note: The expires value will vary)

Mitigation Analysis:
By explicitly initializing the cookie attributes, we have fixed the vulnerabilities:

secure: The cookie will now only be sent over a secure HTTPS connection.
HttpOnly: The cookie is now inaccessible to client-side scripts, protecting it from XSS-based theft.
SameSite=Strict: The cookie will not be sent on cross-site requests, protecting against CSRF attacks.
This exercise demonstrates the critical importance of never relying on default values for security-sensitive configurations. Always explicitly define them to ensure your application remains secure.