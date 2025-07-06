
# 🔐 Secure Flask App with Auth0 & Azure Monitoring

This project demonstrates a production-ready Flask application that integrates Auth0 authentication and Azure observability. It logs user activity and detects suspicious behavior using Azure Monitor and KQL.

---

## 📦 Setup Steps

### 🔐 Auth0 Configuration

1. **Create a new Auth0 Tenant** at [auth0.com](https://auth0.com/).
2. **Register a new Application** (Regular Web App).
3. In **Application Settings**:
   - Allowed Callback URLs:  
     `https://<your-app-name>.azurewebsites.net/callback`
   - Allowed Logout URLs:  
     `https://<your-app-name>.azurewebsites.net/logout`
4. Copy the following:
   - **Client ID**
   - **Client Secret**
   - **Domain**

---

### ☁️ Azure Deployment

1. Deploy the Flask app to **Azure App Service** (using Git or ZIP).
2. In **App Service → Configuration**, add environment variables (from `.env`).
3. Set **Startup Command** to:
   ```bash
   gunicorn --bind=0.0.0.0 --timeout 600 app:app
   ```
4. Enable:
   - App Service logs
   - Diagnostic settings to send logs to a **Log Analytics Workspace**

---

### 🛠️ `.env` File (for local development)

```
FLASK_APP=app.py
FLASK_ENV=production
APP_SECRET_KEY=your_flask_secret_key

AUTH0_CLIENT_ID=your_auth0_client_id
AUTH0_CLIENT_SECRET=your_auth0_client_secret
AUTH0_DOMAIN=your_auth0_domain
AUTH0_CALLBACK_URL=https://your-app-name.azurewebsites.net/callback
AUTH0_AUDIENCE=https://your-api-identifier
```

📌 **Note**: Do not commit `.env` to version control. Instead, share `.env.example` with placeholder values.

---

## 🧾 Logging and Detection Logic

- The Flask app logs:
  - Successful logins: user_id, email, timestamp
  - Access to `/protected`: user_id, IP, timestamp
  - Unauthorized access attempts
- Logs are sent using `app.logger.info()` or `app.logger.warning()`.
- Azure collects logs using `AppServiceConsoleLogs`.

---

## 🔍 KQL Query (Suspicious Access Detection)

```kql
AppServiceConsoleLogs
| where TimeGenerated > ago(15m)
| where ResultDescription has "event=authorized_access" and ResultDescription has "path=/protected"
| extend user_id = extract(@"user_id=([^\s,]+)", 1, ResultDescription)
| extend name = extract(@"name=\"([^\"]+)\"", 1, ResultDescription)
| extend timestamp = extract(@"timestamp=([^\s,]+)", 1, ResultDescription)
| summarize access_count = count(), latest_timestamp = max(timestamp) by user_id, name
| where access_count > 10
| project user_id, name, latest_timestamp, access_count
| order by access_count desc
```

---

## 🔔 Azure Monitor Alert Logic

- **Trigger**: If any user accesses `/protected` route more than 10 times in 15 minutes.
- **Log Analytics condition**: Custom KQL query output count > 0
- **Severity**: 3 (Low)
- **Action Group**: _Skipped due to permission constraints_

---

## ✅ Summary

| Component | Description |
|----------|-------------|
| **Auth0** | Handles secure login (SSO) |
| **Flask** | Backend app logging user behavior |
| **Azure App Service** | Hosts the app |
| **Log Analytics** | Captures logs |
| **KQL** | Identifies suspicious patterns |
| **Alerts** | Notifies on excessive access |
