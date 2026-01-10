# Aruba ClearPass API Setup Guide

This guide describes how to generate the **API Client ID** and **Client Secret** required for `cert-automate` to interact with Aruba ClearPass Policy Manager (CPPM).

## Prerequisites
- Administrative access to ClearPass Policy Manager.
- Ensure the **OAuth2 API User Access** service is enabled (Default via wizard if missing).

## Steps

### 1. Navigate to API Clients
1.  Log in to **ClearPass Guest**. (Note: API Client configuration is often found in the Guest module, even for Policy Manager access).
2.  Go to **Administration > API Services > API Clients**.

### 2. Create a New Client
1.  Click **Create API client** (top right).
2.  Fill in the following details:
    -   **Name**: `cert-automate` (or any identifier).
    -   **Description**: "Certificate Automation Service".
    -   **Operator Profile**: `Super Administrator` (or a custom profile with `Certificates > Read, Write` access).
    -   **Grant Type**: Select **Client credentials**.
    -   **Access Token Lifetime**: Default is usually fine (e.g., 8 hours).

### 3. Save and Record Credentials
1.  Click **Create**.
2.  **IMPORTANT**: The system will display the **Client ID** and **Client Secret**.
    -   Copy these values immediately. The secret cannot be viewed again later.

## Configuration in Cert-Automate
Once you have the credentials, configure your service in `cert-automate` as follows:

-   **Type**: `clearpass`
-   **Host**: `https://<your-cppm-ip>` (Ensure HTTPS)
-   **Client ID**: Paste the Client ID from step 3.
-   **Client Secret**: Paste the Client Secret from step 3.
-   **Callback Host** (Optional): The IP address of the `cert-automate` server (so CPPM can reach back to download the certificate).
-   **Additional Nodes** (Optional): Comma-separated list of IP addresses for other nodes in the cluster (e.g., `10.1.1.2, 10.1.1.3`).
    -   The system will automatically generate unique download URLs for each node to prevent token conflicts.
    -   Certificates will be pushed to the **Publisher** (Primary Host) and all **Subscribers** (Additional Nodes) in sequence.
