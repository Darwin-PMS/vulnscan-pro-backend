# VulnScan Pro - Postman Collection

Complete API collection for VulnScan Pro - Web & Mobile Security Scanner

## Files Included

| File | Description |
|------|-------------|
| `postman-collection.json` | Full API collection |
| `postman-environment.json` | Development environment |

## Quick Start

### 1. Import Collection
1. Open Postman
2. Click **Import** → **Import File**
3. Select `postman-collection.json`
4. Click **Import**

### 2. Import Environment
1. Click **Import** → **Import File**
2. Select `postman-environment.json`
3. Click **Import**

### 3. Select Environment
1. Click the environment dropdown (top right)
2. Select **VulnScan Pro - Development**

### 4. Login
1. Go to **Authentication** → **Login**
2. Click **Send**
3. Copy the `token` from response
4. The token will be auto-saved to `{{authToken}}` variable

## Test Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@vulnscan.pro | Password@123 |
| User | john@example.com | Password@123 |
| Pro User | jane@example.com | Password@123 |
| Enterprise | enterprise@example.com | Password@123 |

## API Endpoints Overview

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login
- `GET /api/auth/me` - Get current user
- `POST /api/auth/logout` - Logout

### Scans
- `POST /api/scans` - Start new scan
- `GET /api/scans` - Get all scans
- `GET /api/scans/:scanId/results` - Get results
- `GET /api/scans/dashboard` - Dashboard stats

### Dorks (GHDB)
- `GET /api/dorks` - Get all dork patterns
- `GET /api/dorks/categories` - Get categories
- `POST /api/dorks/scan` - Run GHDB scan

### Scan Modules
- `GET /api/scan-modules` - Get all modules
- `POST /api/scan-modules/owasp/scan` - Run OWASP scan
- `POST /api/scan-modules/multi-scan` - Run multi-module scan

### AI Assistant
- `POST /api/ai/assistant` - Chat with AI
- `GET /api/ai/chat-history` - Get chat history

### Admin
- `GET /api/admin/users` - Get all users
- `GET /api/admin/stats` - System statistics

### Logs
- `GET /api/logs/stats` - Log file statistics
- `GET /api/logs/requests` - Request logs
- `GET /api/logs/errors` - Error logs

## Using the Collection

### 1. Run a Vulnerability Scan
```
Authentication → Login (Get Token)
↓  
Scans → Start New Scan
↓  
Scans → Get Scan Status (use scanId from response)
↓  
Scans → Get Scan Results
```

### 2. Run GHDB Dork Scan
```
Authentication → Login
↓
Dorks → Get Dork Categories
↓
Dorks → Run GHDB Scan
↓
Scans → Get Scan Results
```

### 3. Check System Logs
```
Authentication → Login (as admin)
↓
Logs → Get Log Stats
↓
Logs → Get Request Logs
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `baseUrl` | API base URL | http://localhost:5000/api |
| `userEmail` | Login email | admin@vulnscan.pro |
| `userPassword` | Login password | Password@123 |
| `authToken` | JWT token | (auto-filled) |
| `scanId` | Current scan ID | (auto-filled) |
| `targetUrl` | Target for scanning | https://example.com |

## Testing Different Subscription Tiers

1. **Free Tier** - Login as `john@example.com`
2. **Pro Tier** - Login as `jane@example.com`  
3. **Enterprise** - Login as `enterprise@example.com`
4. **Admin** - Login as `admin@vulnscan.pro`

## API Response Examples

### Successful Login
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": 1,
    "email": "admin@vulnscan.pro",
    "role": "admin",
    "subscription_tier": "enterprise"
  }
}
```

### Start Scan
```json
{
  "success": true,
  "scan_id": "scan_abc123",
  "status": "pending",
  "message": "Scan started successfully"
}
```

### Scan Results
```json
{
  "success": true,
  "scan": {
    "scan_id": "scan_abc123",
    "target_url": "https://example.com",
    "status": "completed",
    "total_vulnerabilities": 5,
    "critical_count": 1,
    "high_count": 2,
    "medium_count": 1,
    "low_count": 1
  },
  "vulnerabilities": [
    {
      "id": 1,
      "title": "SQL Injection",
      "severity": "critical",
      "url": "https://example.com/login"
    }
  ]
}
```

## Troubleshooting

### 401 Unauthorized
- Make sure you've logged in and have a valid token
- Token expires after 24 hours

### 403 Forbidden  
- Some endpoints require admin role
- Login as admin@vulnscan.pro

### 404 Not Found
- Check the endpoint URL in the request
- Ensure the resource exists

---

**Version:** 2.0.0  
**Last Updated:** 2026-04-02
