# Project Standards & Rulebook

**Enforced By**: Project Lead / Lead Architect  
**Scope**: All contributions and maintenance operations.

## 1. Golden Rules
1.  **`dev` is the Source of Truth**: All code changes, debugging, and testing happen in `dev/app`. Never edit files in `prod/` directly.
2.  **No Silent Releases**: Every package event must be accompanied by a Changelog entry.
3.  **Manual Packaging**: We do not auto-deploy. Deployment to Production is a deliberate, manual action triggered via the build script.

## 2. Folder Structure Standards
The project directory must strictly adhere to this schema:

| Directory | Purpose | Rules |
| :--- | :--- | :--- |
| **`dev/`** | Active Development | Contains the `Dockerfile`, `docker-compose.yml`, and `app/` source. |
| **`prod/`** | Production Deployment | **READ-ONLY**. Overwritten by the build script. Contains sanitized code only. |
| **`code_backup/`** | Historical Archive | Contains uncompressed snapshots of previous builds (e.g., `cert_automate_v1.0_build3/`). **NEVER DELETE** old backups without PLM approval. |
| **`input_certificates/`** | Runtime Data | Place `fullchain.pem` and `privkey.pem` here. Ignored by git/builds. |
| **`build_scripts/`** | Tooling | Contains `build.py` and version metadata. |
| **`documentation/`** | Knowledge Base | Contains Vision, Architecture, Specs, and Standards. |

## 3. Development & Backup Workflow
### The Cycle
1.  **Develop**: Make changes in `dev/app`.
2.  **Verify**: Run `docker-compose up` in `dev/` to test.
3.  **Document**: Update `documentation/changelog.md` and `technical_specs.md` (if API changed).
4.  **Package**: Run `python3 build_scripts/build.py`.

### Backup Policy
- The build script automatically creates a **full, unzipped copy** of the source code into `code_backup/cert_automate_v<Ver>_build<ID>`.
- **Restoration**: To restore a previous version, delete `dev/app` and copy the contents of a backup folder back into `dev/app`.

## 4. Packaging & Production
### The Build Process
The `build.py` script performs the following **atomic** operations:
1.  **Increments Build Number**: Updates `version_info.json`.
2.  **Snapshot**: Copies `dev` source to `code_backup/`.
3.  **Sanitize**: Filters out `__pycache__`, `.DS_Store`, `venv`, and `*.pyc`.
4.  **Deploy**: Nukes `prod/app` and replaces it with the sanitized snapshot.

### Triggering a Release
Run the command strictly from the root:
```bash
cd build_scripts && python3 build.py
```

## 5. Documentation Standards
- **Changelog**: Must follow [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.
    - **Added**: New features.
    - **Changed**: Changes in existing functionality.
    - **Fixed**: Bug fixes.
- **Architecture**: If you change the code structure (e.g., add a new Handler), you **MUST** update `documentation/architecture.md` diagram and text.
- **Specs**: If you change API endpoints or Config format, you **MUST** update `documentation/technical_specs.md`.
