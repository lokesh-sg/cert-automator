# Workspace Rules — CertAutomator

## Workspace Structure & Backup Rules
1. **`dev/app` is the Single Source of Truth**: All source code changes, bug fixes, and feature work MUST occur exclusively inside `dev/app/`.
2. **`code_backup/` Preservation Rule**: The `code_backup/` directory MUST NEVER be deleted, emptied, or removed. It contains all historical release archives.
3. **Git Ignore Safety**: `code_backup/`, `prod/app/`, secrets (`auth.json`, `config.yaml`), logs (`*.log`), tarballs (`*.tar`), and zip archives (`*.zip`) MUST remain strictly ignored in `.gitignore` and NEVER pushed to public repositories.
4. **Build Automation**: All code compilation and prod deployment MUST use `python3 build_scripts/build.py`.
