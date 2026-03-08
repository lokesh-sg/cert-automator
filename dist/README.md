# CertAutomator Distribution Package

This folder contains everything needed to package and share CertAutomator as a portable Docker image.

## 📦 How to Create the Shareable Package

1.  Open your Terminal.
2.  Navigate to this `dist/` folder.
3.  Run the packaging script:
    ```bash
    ./package_for_sharing.sh
    ```

### What This Script Does:
- **Builds** the Docker image for both Intel/AMD and Apple Silicon/ARM.
- **Exports** them to two files: `cert-automator-amd64.tar` and `cert-automator-arm64.tar`.

---

## 🚀 How to Deploy on a New Server

### Option A: Using a Docker Registry (Easiest)
If you have pushed the image to a registry (like Docker Hub) using the script:

1.  **Update docker-compose.yml**:
    Set the `image:` field to your repository name (e.g., `image: lokeshg/cert-automator:latest`).

2.  **Start the Server**:
    ```bash
    docker compose up -d
    ```
    Docker will automatically pull the correct version for your hardware!

---

### Option B: Using Portable Tarballs
If you are sharing the files directly:

1.  **Select the correct file**:
    -   **Intel/AMD servers**: Use `cert-automator-amd64.tar`
    -   **Apple Silicon/ARM**: Use `cert-automator-arm64.tar`

2.  **Load the Image**:
    ```bash
    docker load < cert-automator-[arch].tar
    ```

3.  **Update docker-compose.yml**:
    Ensure the `image:` line matches the loaded version (e.g., `image: cert-automator:amd64`).

4.  **Start the Server**:
    ```bash
    docker compose up -d
    ```

The app will then be available at `http://[server-ip]:5050`.
