# Quick Setup: GitHub Secrets for NPM Publishing

## 🔑 Generate NPM Token

### Method 1: npmjs.com Website (Recommended)

1. **Navigate**: https://www.npmjs.com/settings/liamhelmer/tokens
2. **Click**: "Generate New Token" → "Automation"
3. **Name**: `GitHub Actions - claude-flow-ui`
4. **Copy**: The generated token (shown only once!)

### Method 2: Command Line

```bash
npm login  # Login as liamhelmer
npm token create --type automation --description "GitHub Actions - claude-flow-ui"
```

Copy the token from the output.

## 🔐 Add Token to GitHub

### Direct Link
https://github.com/liamhelmer/claude-flow-ui/settings/secrets/actions/new

### Manual Steps

1. **Go to**: https://github.com/liamhelmer/claude-flow-ui
2. **Click**: Settings → Secrets and variables → Actions
3. **Click**: "New repository secret"
4. **Configure**:
   - Name: `NPM_TOKEN`
   - Secret: [Paste your npm token]
5. **Click**: "Add secret"

## ✅ Verify Setup

### Check Secret Exists

1. Go to: https://github.com/liamhelmer/claude-flow-ui/settings/secrets/actions
2. Look for: `NPM_TOKEN` in the list
3. Should show: "Updated X seconds/minutes ago"

### Test Workflow

```bash
# Bump version
npm version patch

# Commit and push
git push origin main

# Watch workflow
# https://github.com/liamhelmer/claude-flow-ui/actions
```

## 🚀 What Happens Next

When you push a version change to `main`:

1. ✅ Workflow detects version change
2. ✅ Builds and tests package
3. ✅ Creates git tag `v1.4.2`
4. ✅ Creates GitHub release
5. ✅ Publishes to npmjs.com (if `NPM_TOKEN` exists)
6. ✅ Publishes to GitHub Packages (always)

## ⚠️ Security Notes

- **Never commit** the NPM token to git
- **Rotate tokens** every 90 days
- **Use automation tokens** (not publish tokens)
- **Revoke old tokens** after rotation

## 🔄 Token Rotation

Every 90 days:

```bash
# 1. Generate new token on npmjs.com
# 2. Update GitHub secret with new token
# 3. Revoke old token on npmjs.com
```

## 📋 Token Permissions

Your NPM token needs:
- ✅ **Automation** type (full publishing rights)
- ❌ **Read-only** (insufficient for publishing)

## 🛠️ Troubleshooting

### Token Not Working

**Symptom**: `401 Unauthorized` during publish

**Solution**:
1. Regenerate token on npmjs.com
2. Update `NPM_TOKEN` secret in GitHub
3. Ensure token type is "Automation"

### Secret Not Found

**Symptom**: Workflow skips npmjs publish

**Check**:
1. Secret name is exactly `NPM_TOKEN` (case-sensitive)
2. Secret is in Actions secrets (not Dependabot or Codespaces)
3. Repository settings allow Actions to use secrets

### Workflow Not Triggering

**Check**:
1. Pushed to `main` branch
2. `package.json` file modified
3. Version number changed
4. Workflow file exists: `.github/workflows/publish-package.yml`

## 📞 Support

- NPM Docs: https://docs.npmjs.com/creating-and-viewing-access-tokens
- GitHub Secrets: https://docs.github.com/en/actions/security-guides/encrypted-secrets
- Repository Issues: https://github.com/liamhelmer/claude-flow-ui/issues
