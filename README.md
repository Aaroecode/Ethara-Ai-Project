# Team Task Manager (Full-Stack)

A lightweight full-stack app for project/task management with role-based access (Admin/Member).

## Features
- Authentication: signup/login
- Admin can create projects and add members
- Project members can create/update tasks
- Dashboard with status counts + overdue summary
- SQLite database with proper relationships and constraints

## Tech Stack
- Backend: Python (WSGI + stdlib)
- Database: SQLite
- Frontend: Vanilla HTML/JS

## Local Run
```bash
python server.py
```
App: `http://localhost:8080`

## API Endpoints
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/projects` (admin)
- `GET /api/projects`
- `POST /api/projects/:id/members` (admin)
- `POST /api/tasks`
- `PUT /api/tasks/:id`
- `GET /api/dashboard`

## Railway Deployment
1. Push this repo to GitHub.
2. On Railway, create **New Project → Deploy from GitHub Repo**.
3. Set start command: `python server.py`.
4. Add env vars:
   - `APP_SECRET` (required)
   - `PORT` (Railway injects this automatically)
5. Deploy and copy the generated live URL.

## Submission Checklist
- Live URL (Railway)
- GitHub repository URL
- Updated README
- 2–5 minute demo video showing signup/login, project creation, task flow, dashboard
