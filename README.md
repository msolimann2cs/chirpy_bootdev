# Chirpy 🐦

Chirpy is a lightweight, scalable social media API server built with Go and PostgreSQL, inspired by Twitter. Developed as part of the Boot.dev server-building course, this project demonstrates robust, production-ready backend practices, including secure authentication, database migrations, JWT handling, and RESTful API design.

## 🌟 Features

- **User Authentication:** Secure signup, login, and JWT token management.
- **Secure Endpoints:** Protect endpoints with JWT authentication and refresh tokens.
- **Chirp Management:** Post, retrieve, filter, sort, and delete chirps (tweets).
- **Webhook Integration:** Upgrade user statuses securely via webhook events from third-party services (e.g., Polka).
- **Refresh Tokens:** Issue and revoke refresh tokens securely stored in PostgreSQL.
- **Advanced Queries:** Sort and filter chirps by creation date and author ID.
- **Admin Metrics:** Monitor and reset application metrics (development only).

## 🚀 Why Chirpy?

Chirpy serves as an excellent example for anyone looking to understand:

- How to build secure RESTful APIs using Go.
- JWT authentication and secure handling of user sessions.
- Managing database migrations using Goose.
- Clean, maintainable Go project structure.
- Integration and security best practices for webhooks and API keys.

Whether you're learning backend development or building your own Go APIs, Chirpy provides a solid foundation to learn from and extend.

## 🛠 Tech Stack

- **Go (1.24+)**
- **PostgreSQL**
- **JWT (golang-jwt)**
- **bcrypt** for password hashing
- **Goose** for database migrations
- **SQLC** for type-safe queries
- **dotenv** for managing environment variables

## 📚 Setup & Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/chirpy.git
cd chirpy
```

### Step 2: Set up environment variables

Create a `.env` file in your project's root:

```env
DB_URL=your_postgres_db_url
JWT_SECRET=your_jwt_secret
POLKA_KEY=your_polka_api_key
PLATFORM=dev
```

Generate a strong secret for JWT and Polka:

```bash
openssl rand -base64 64
```
Polka is used to demonstrate webhooks and isn't a real provider so use any generated API key in the env)

### Step 3: Run database migrations

```bash
goose postgres "$DB_URL" up
```

### Step 4: Install dependencies and run

```bash
go mod tidy
go build -o out && ./out
```

Server runs on `http://localhost:8080`

## 🔑 API Endpoints

### Users

- `POST /api/users` - Create user
- `PUT /api/users` - Update user's email/password
- `POST /api/login` - User login, returns JWT & refresh token
- `POST /api/refresh` - Refresh JWT using refresh token
- `POST /api/revoke` - Revoke refresh token

### Chirps

- `POST /api/chirps` - Create chirp
- `GET /api/chirps` - Retrieve all chirps (supports filtering and sorting)
- `GET /api/chirps/{chirpID}` - Retrieve chirp by ID
- `DELETE /api/chirps/{chirpID}` - Delete chirp by ID (authenticated)

### Webhooks

- `POST /api/polka/webhooks` - Upgrade user to "Chirpy Red" status (requires API key)

### Admin (Development Only)

- `GET /admin/metrics` - Display metrics
- `POST /admin/reset` - Reset metrics and delete all users (dev only)

## 🎓 Attribution

Chirpy was created following the [Boot.dev](https://boot.dev/) HTTP Server course, which provides comprehensive guidance on building production-ready web servers.

---

Happy chirping! 🐤
