# Release Process

**Author**: Lokesh G

Follow this checklist to ship a new version of CertAutomator safely and consistently.

## 1. Prepare
- [ ] **Sanitize**: Ensure `dev/app` contains no secret files (`config.yaml`, `auth.json`).
- [ ] **Changelog**: Update `dev/CHANGELOG.md` with new features and fixes under a new version header (e.g., `## [1.2.0]`).

## 2. Build
Run the build automation script. This will increment the build number, archive the code, and update the `prod/` directory.

```bash
python3 build_scripts/build.py
```

*Note the output version, e.g., `v1.1.0.20260109.03`.*

## 3. Package & Push Docker
Run the packaging script to build multi-arch images and push them to Docker Hub.

```bash
./dist/package_for_sharing.sh
```
- **Tag**: The script pushes `latest`.
- **Specific Tag**: Manually tag the specific build to preserve history:
  ```bash
  docker buildx imagetools create -t lokeshsg/cert-automator:v1.1.0.20260109.03 lokeshsg/cert-automator:latest
  ```

## 4. Git Release
Commit the changes (changelog + build bump) and tag the commit.

```bash
git add .
git commit -m "Release v1.1.0.20260109.03"
git push origin main
```

**Tagging**:
```bash
# Tag with the specific build ID
git tag -a v1.1.0.20260109.03 -m "Release v1.1.0.20260109.03"
git push origin v1.1.0.20260109.03
```

## 5. GitHub Release
1. Go to [GitHub Releases](https://github.com/lokesh-sg/cert-automator/releases).
2. Draft a new release (or edit existing).
3. **Tag**: Select `v1.1.0.20260109.03`.
4. **Description**: Copy the relevant section from `dev/CHANGELOG.md`.
5. **Assets**: Upload the `.tar` files generated in Step 3 (optional, for offline users).
