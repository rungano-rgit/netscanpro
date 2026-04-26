# NetscanPro

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Deploy](https://img.shields.io/badge/Deploy-Ready-brightgreen.svg)]()

## Enterprise Network Security Scanner

NetscanPro is a professional, multi-user network security scanner with firewall integration, audit logging, and comprehensive reporting capabilities.

### Features

- **Multi-user Authentication** with role-based access (Admin/User)
- **Advanced Network Scanning** with ping sweep, TCP connect, and ARP discovery
- **Firewall Integration** for Windows block/unblock
- **Comprehensive Reports** with export support
- **Real-time Notifications** and audit logging
- **Database Backups** and secure export
- **Built-in API Documentation** for developers
- **Production Ready** with Docker, Gunicorn, and Render support

### Quick Start

```bash
# Clone the repository
git clone https://github.com/rungano-rgit/netscanpro.git
cd netscanpro

# Create virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
copy .env.example .env

# Configure env values in .env
# Run the application
python app.py
```

### Deployment

#### Render

1. Create a new Render Web Service.
2. Connect your GitHub repository `rungano-rgit/netscanpro`.
3. Set the build command to:

```bash
pip install -r requirements.txt
```

4. Set the start command to:

```bash
gunicorn wsgi:app
```

5. Add environment variables in Render:

- `FLASK_ENV=production`
- `FLASK_SECRET_KEY=your-production-secret`
- `SCANNER_DB=scanner.db`
- `SCANNER_LOG=audit.log`

6. Deploy.

> Note: SQLite is suitable for small deployments. For larger production workloads, replace SQLite with an external database and update `app.py` accordingly.

#### Docker

Build and run with Docker:

```bash
docker build -t netscanpro .
docker run -p 5000:5000 --env FLASK_ENV=production --env FLASK_SECRET_KEY=your-secret netscanpro
```

Or use Docker Compose:

```bash
docker compose up --build
```

### Environment Variables

Use `.env.example` as a template for:

- `FLASK_SECRET_KEY`
- `FLASK_ENV`
- `SCANNER_DB`
- `SCANNER_LOG`

### Files Added

- `.gitignore`
- `README.md`
- `LICENSE`
- `.env.example`
- `Procfile`
- `runtime.txt`
- `Dockerfile`
- `docker-compose.yml`
- `wsgi.py`

### License

This project is licensed under the MIT License.
