# GitHub OAuth Setup

This guide explains how to set up GitHub OAuth authentication for user accounts.

## Prerequisites

1. Install Flask-Dance:
   ```bash
   pip install flask-dance
   ```

2. Create a GitHub OAuth App:
   - Go to GitHub Settings > Developer settings > OAuth Apps
   - Click "New OAuth App"
   - Fill in the details:
     - Application name: `sec-certs`
     - Homepage URL: `https://your-domain.com`
     - Authorization callback URL: `https://your-domain.com/auth/github/authorized`

## Configuration

Add the following environment variables or config settings:

```python
# In your Flask config
GITHUB_OAUTH_CLIENT_ID = "your_github_client_id"
GITHUB_OAUTH_CLIENT_SECRET = "your_github_client_secret"
```

Or set environment variables:
```bash
export GITHUB_OAUTH_CLIENT_ID="your_github_client_id"
export GITHUB_OAUTH_CLIENT_SECRET="your_github_client_secret"
```

## Features

When properly configured, users can:

1. **Sign up with GitHub** - Creates new account using GitHub profile
2. **Sign in with GitHub** - Login to existing linked account
3. **Link GitHub account** - Connect GitHub to existing email-based account
4. **Auto-confirm email** - GitHub accounts are automatically email-confirmed

## Security Notes

- GitHub users get auto-confirmed email addresses
- OAuth users can still set passwords for traditional login
- Existing accounts can be linked to GitHub using the same email address
- GitHub connection status is shown in user profiles

## Fallback

If Flask-Dance is not installed or GitHub OAuth is not configured, the GitHub login buttons will not appear, and the system will fall back to traditional email/password authentication.