# NPM Publishing Setup Guide

This guide walks you through setting up automatic publishing to npmjs.com and GitHub Packages.

## Prerequisites

- GitHub account with repository access
- npmjs.com account (username: `liamhelmer`)
- Package name: `@liamhelmer/claude-flow-ui`

## Step 1: Generate NPM Access Token

### Option A: Via npmjs.com Website

1. Go to https://www.npmjs.com/
2. Log in with your account (`liamhelmer`)
3. Click your profile picture → **Access Tokens**
4. Click **Generate New Token** → **Automation**
5. Give it a name: `GitHub Actions - claude-flow-ui`
6. Click **Generate Token**
7. **IMPORTANT**: Copy the token immediately (you won't see it again)

### Option B: Via npm CLI

```bash
# Login to npm
npm login

# Generate automation token
npm token create --read-only=false
```

Copy the token value from the output.

## Step 2: Add NPM Token to GitHub Secrets

1. Go to your repository: https://github.com/liamhelmer/claude-flow-ui
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `NPM_TOKEN`
5. Value: Paste the token from Step 1
6. Click **Add secret**

## Step 3: Configure package.json for GitHub Packages

Your `package.json` already has the correct configuration:

```json
{
  "name": "@liamhelmer/claude-flow-ui",
  "publishConfig": {
    "access": "public"
  }
}
```

For GitHub Packages, you may also want to add a `.npmrc` file in your repository:

```
@liamhelmer:registry=https://npm.pkg.github.com
```

However, this is optional as the GitHub Action handles the registry switching.

## Step 4: Test the Workflow

### Manual Test (Without Publishing)

```bash
# Verify package can be packed
npm pack --dry-run

# Check what files will be included
npm publish --dry-run
```

### Trigger Automatic Publish

1. Update the version in `package.json`:
   ```bash
   npm version patch  # or minor, or major
   ```

2. Commit and push to main:
   ```bash
   git add package.json package-lock.json
   git commit -m "chore: bump version to 1.4.2"
   git push origin main
   ```

3. Watch the GitHub Actions workflow:
   - Go to **Actions** tab in your repository
   - Click on the **Publish Package** workflow
   - Monitor the progress

## How It Works

### Workflow Triggers

The workflow runs when:
- A commit is pushed to `main` branch
- The `package.json` file is modified
- The version in `package.json` has changed
- The version tag doesn't already exist

### What Happens

1. **Version Check**: Compares current version with previous commit
2. **Build**: Runs linting and production build
3. **Tag Creation**: Creates `vX.Y.Z` git tag
4. **GitHub Release**: Creates a GitHub release with the tag
5. **Publish to npmjs**: Publishes to npmjs.com (if `NPM_TOKEN` exists)
6. **Publish to GitHub**: Publishes to GitHub Packages (always)
7. **Summary**: Posts a summary with links and installation instructions

### Conditional Publishing

**npmjs.com publishing is gated by the `NPM_TOKEN` secret:**

```yaml
- name: Publish to npmjs (if token available)
  if: secrets.NPM_TOKEN != ''
  run: npm publish
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

- name: Skip npmjs publish (no token)
  if: secrets.NPM_TOKEN == ''
  run: |
    echo "⚠️ NPM_TOKEN secret not found, skipping npmjs publish"
```

If the secret is not configured, the workflow will skip npmjs publishing but still publish to GitHub Packages.

## Workflow Features

### ✅ Automatic Tagging
- Creates git tag `vX.Y.Z` based on package.json version
- Pushes tag to remote repository

### ✅ GitHub Release
- Auto-generates release notes
- Links to installation instructions
- References CHANGELOG.md

### ✅ Dual Registry Publishing
- **npmjs.com**: Public package (if token configured)
- **GitHub Packages**: Always published

### ✅ Build Verification
- Runs linting before publishing
- Ensures production build succeeds
- Prevents publishing broken code

### ✅ Idempotency
- Checks if version tag already exists
- Skips publish if tag exists
- Prevents duplicate releases

## Installation After Publishing

### From npmjs.com
```bash
npm install @liamhelmer/claude-flow-ui
# or
npx @liamhelmer/claude-flow-ui
```

### From GitHub Packages
```bash
# Add .npmrc to your project
echo "@liamhelmer:registry=https://npm.pkg.github.com" >> .npmrc

# Install
npm install @liamhelmer/claude-flow-ui
```

## Monitoring

### GitHub Actions
- View workflow runs: https://github.com/liamhelmer/claude-flow-ui/actions
- Check logs for each step
- Review publish summary in the workflow run

### npmjs.com
- Package page: https://www.npmjs.com/package/@liamhelmer/claude-flow-ui
- Download stats, versions, and dependencies

### GitHub Packages
- Packages page: https://github.com/liamhelmer/claude-flow-ui/packages
- View package versions and details

## Troubleshooting

### NPM Token Issues

**Error**: `401 Unauthorized`
```
Solution: Regenerate NPM token and update GitHub secret
```

**Error**: `403 Forbidden`
```
Solution: Ensure token has "Automation" permission, not "Read-only"
```

### GitHub Packages Issues

**Error**: `404 Not Found`
```
Solution: Ensure package.json has correct "name" field with @username/ prefix
```

**Error**: `409 Conflict`
```
Solution: Version already published, bump version number
```

### Workflow Not Triggering

**Check**:
1. Workflow file in `.github/workflows/publish-package.yml`
2. Commit pushes to `main` branch
3. `package.json` file is modified in the commit
4. Version in `package.json` has changed

### Tag Already Exists

If a tag exists but the release failed:

```bash
# Delete remote tag
git push origin --delete v1.4.2

# Delete local tag
git tag -d v1.4.2

# Push package.json change again to retrigger
git commit --amend --no-edit
git push origin main --force
```

## Security Best Practices

### NPM Token Security
- ✅ Use "Automation" token type (not "Publish")
- ✅ Store token in GitHub Secrets (encrypted)
- ✅ Rotate tokens periodically (every 90 days)
- ✅ Revoke old tokens after rotation
- ❌ Never commit tokens to repository
- ❌ Never log tokens in workflow output

### GitHub Token Security
- ✅ Uses built-in `GITHUB_TOKEN` (auto-managed)
- ✅ Scoped to repository permissions
- ✅ Automatically expires after workflow run
- ❌ No manual token management needed

## Version Management

### Semantic Versioning

Follow semver (https://semver.org/):

```bash
# Patch release (1.4.2 → 1.4.3) - bug fixes
npm version patch

# Minor release (1.4.2 → 1.5.0) - new features, backwards compatible
npm version minor

# Major release (1.4.2 → 2.0.0) - breaking changes
npm version major
```

### Pre-release Versions

```bash
# Alpha release (1.4.2 → 1.4.3-alpha.0)
npm version prerelease --preid=alpha

# Beta release (1.4.2 → 1.4.3-beta.0)
npm version prerelease --preid=beta
```

### Version Workflow

```bash
# 1. Update version
npm version patch -m "chore: bump version to %s"

# 2. Push changes (triggers publish)
git push origin main

# 3. Monitor GitHub Actions
# Go to Actions tab and watch the workflow
```

## Changelog Management

Maintain a `CHANGELOG.md` file to document changes:

```markdown
# Changelog

## [1.4.2] - 2025-10-03

### Added
- WebSocket authentication with Bearer tokens
- Automatic npm publishing workflow

### Fixed
- Production build missing middleware files
- JWKS empty keys issue

### Security
- Token no longer exposed in WebSocket URL
```

This will be linked in the auto-generated GitHub releases.

## Advanced Configuration

### Custom Release Notes

Edit `.github/workflows/publish-package.yml` to customize release body:

```yaml
- name: Create GitHub Release
  uses: actions/create-release@v1
  with:
    body: |
      ## What's New in v${{ needs.check-version.outputs.new-version }}

      [Your custom release notes here]
```

### Publish to Multiple Scopes

To publish under different scopes:

```yaml
- name: Publish to alternate scope
  run: |
    # Temporarily rename package
    npm pkg set name=@altscope/claude-flow-ui
    npm publish --registry=https://registry.npmjs.org
    # Restore original name
    git checkout package.json
```

### Conditional Pre-release

Mark versions with `-alpha`, `-beta` as pre-releases:

```yaml
- name: Create GitHub Release
  with:
    prerelease: ${{ contains(needs.check-version.outputs.new-version, '-') }}
```

## Support

For issues with:
- **Workflow**: Open issue in this repository
- **npmjs.com**: https://docs.npmjs.com/
- **GitHub Packages**: https://docs.github.com/packages
