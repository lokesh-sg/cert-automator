# Release Process

**Author**: Lokesh G
**Updated**: 2026-01-27

Follow this checklist to ship a new version of CertAutomator safely.

## 1. Prepare
- [ ] **Sanitize**: Ensure `dev/app` is clean.
- [ ] **Changelog**: Update `dev/CHANGELOG.md`.
- [ ] **Version**: Bump version in `dev/app/version.json`.

## 2. Git Release
Commit changes and tag the release version.

```bash
git add .
git commit -m "Release vX.Y.Z: Description"
git tag vX.Y.Z
git push origin main --tags
```

## 3. Docker Release
Build and push the multi-tag image to Docker Hub.

```bash
# Login first
docker login

# Setup Builder (Once)
docker buildx create --use

# Build & Push Multi-Arch
docker buildx build --platform linux/amd64,linux/arm64 \
  -t <DOCKER_HUB_USER>/cert-automator:vX.Y.Z \
  -t <DOCKER_HUB_USER>/cert-automator:latest \
  -f dev/Dockerfile dev/ --push
```

## 4. Documentation
Sync the documentation changes.

```bash
cp dev/CHANGELOG.md documentation/changelog.md
```
