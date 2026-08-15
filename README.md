# FS Learning — Real Full-Stack System

This build is a real local full-stack system, not just a mockup.

## Features
- Real username/password login using bcrypt password hashes
- Multiple users
- Admin and normal-user roles
- Course assignment per user
- Video upload and protected video playback with HTTP range support
- PDF resource upload, protected download and per-lesson attachment
- User support/problem messages
- Admin replies and message closing
- User enable/disable
- SQLite database
- Responsive mobile-friendly UI
- FS Learning logo from the supplied image

## Run locally

Install Node.js 18+.

1. Extract this ZIP.
2. Open a terminal in the project folder.
3. Run:
   npm install
4. Start:
   npm start
5. Open:
   http://localhost:3000

## First admin
Username: admin
Password: admin12345

Change the admin password by creating a new admin and disabling/removing the default account before any public deployment.

## Important before internet deployment
- Set a strong SESSION_SECRET environment variable.
- Use HTTPS.
- Set the session cookie `secure: true` behind HTTPS.
- Put uploads on durable storage if your hosting filesystem is ephemeral.
- Use a production database/storage for scale.
- Add rate limiting, CSRF protection and email/password reset before public launch.
- Never share the admin password.

## Android app
This responsive web app can be wrapped as an Android app later with Capacitor, while keeping the same backend.
