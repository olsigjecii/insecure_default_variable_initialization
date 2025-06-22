use actix_web::{
    App, HttpResponse, HttpServer, Responder,
    cookie::{Cookie, SameSite},
    web,
};
use serde::Deserialize;

// Note: In a real application, you'd use a more robust time library like `time` or `chrono`.
// For this example, we'll construct the expiration string manually for simplicity.

#[derive(Deserialize)]
struct LoginCredentials {
    username: String,
    password: String,
}

/// A mock authentication function. In a real application, this would
/// involve password hashing and database lookups.
fn authenticate(creds: &LoginCredentials) -> bool {
    creds.username == "admin" && creds.password == "password"
}

/// A mock token creation function.
fn create_token(username: &str) -> String {
    format!("auth_token_for_{}", username)
}

/// A mock tracker ID creation function.
fn create_tracker(username: &str) -> String {
    format!("tracker_id_for_{}", username)
}

/// **Vulnerable Handler**
/// This handler sets cookies using insecure defaults. In `actix-web`'s cookie API,
/// omitting security flags means they default to less secure settings.
#[actix_web::post("/vulnerable/login")]
async fn vulnerable_login(creds: web::Json<LoginCredentials>) -> impl Responder {
    if !authenticate(&creds) {
        return HttpResponse::BadRequest().body("Incorrect credentials");
    }

    let username = &creds.username;

    // The 'auth' cookie is created without specifying HttpOnly, Secure, or SameSite.
    // This leaves it vulnerable to being read by client-side JavaScript (XSS) and
    // being sent over unencrypted HTTP connections (MITM).
    let auth_cookie = Cookie::new("auth", create_token(username));

    // The 'tracking' cookie is also created with insecure defaults.
    let tracking_cookie = Cookie::new("tracking", create_tracker(username));

    // In actix-web v4, we add cookies directly to the HttpResponse builder.
    HttpResponse::Found()
        .cookie(auth_cookie)
        .cookie(tracking_cookie)
        .append_header(("Location", "/feed"))
        .finish()
}

/// **Secure Handler**
/// This handler mitigates the vulnerability by explicitly setting secure attributes for the cookies.
#[actix_web::post("/secure/login")]
async fn secure_login(creds: web::Json<LoginCredentials>) -> impl Responder {
    if !authenticate(&creds) {
        return HttpResponse::BadRequest().body("Incorrect credentials");
    }

    let username = &creds.username;

    // The 'auth' cookie is now created with secure attributes using the builder pattern.
    let auth_cookie = Cookie::build("auth", create_token(username))
        .path("/")
        .secure(true) // Ensures the cookie is only sent over HTTPS.
        .http_only(true) // Prevents access from client-side scripts (mitigates XSS).
        .same_site(SameSite::Strict) // Prevents the browser from sending the cookie along with cross-site requests.
        .max_age(actix_web::cookie::time::Duration::hours(1)) // Set an expiration
        .finish();

    // The 'tracking' cookie is also made secure. While it may not be as sensitive
    // as the auth cookie, it's good practice to secure all cookies.
    let tracking_cookie = Cookie::build("tracking", create_tracker(username))
        .path("/")
        .secure(true)
        .http_only(true) // Trackers should also be HttpOnly to prevent manipulation.
        .same_site(SameSite::Strict)
        .max_age(actix_web::cookie::time::Duration::hours(1))
        .finish();

    HttpResponse::Found()
        .cookie(auth_cookie)
        .cookie(tracking_cookie)
        .append_header(("Location", "/feed"))
        .finish()
}

/// A simple handler for the /feed endpoint to simulate a successful redirect.
#[actix_web::get("/feed")]
async fn feed() -> impl Responder {
    HttpResponse::Ok().body("Welcome to your feed!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Server running at http://127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .service(vulnerable_login)
            .service(secure_login)
            .service(feed)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
