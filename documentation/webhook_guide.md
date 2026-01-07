# Generic Webhook Handler Guide

The **Generic Webhook Handler** allows you to push certificates to any system that supports a REST API (or any HTTP endpoint) without needing a dedicated plugin. It is designed for maximum flexibility, allowing you to construct custom JSON payloads containing your certificate data.

## 1. Getting Started

To use the Webhook Handler, you can either:
1.  **Directly Add a Service** and select `webhook` as the Type.
2.  **Create a Custom Type** (e.g., "My Custom Firewall") via "Manage Services > ⚙️ Manage Types", and set its Base Handler to `webhook`.

## 2. Configuration Fields

When you select the `webhook` type, the following fields will appear:

### Target URL
The full HTTP or HTTPS endpoint where the request will be sent.
*   **Example**: `https://192.168.1.50/api/v1/system/ssl/upload`
*   **Note**: If the target uses a self-signed certificate, the system *currently* defaults to verifying SSL. (Future update: allow disabling verification).

### Method
The HTTP verb to use.
*   `POST`: Most common for creating/uploading.
*   `PUT`: Common for updating existing resources.
*   `PATCH`: For partial updates.

### Headers (JSON)
A JSON object representing HTTP headers to include in the request. This is typically used for authentication.
*   **Format**: Must be valid JSON.
*   **Example (Bearer Token)**:
    ```json
    {
      "Authorization": "Bearer YOUR_ACCESS_TOKEN",
      "Content-Type": "application/json"
    }
    ```
*   **Example (API Key)**:
    ```json
    {
      "X-API-Key": "abc-123-xyz"
    }
    ```

### Body Template (JSON/Text)
This is where you define the **payload structure**. You write standard JSON (or text), and use specific **Placeholders** that the system will replace with the actual certificate contents at runtime.

#### Available Placeholders:
*   `{CERT}`: The PEM-encoded Leaf Certificate.
*   `{KEY}`: The PEM-encoded Private Key.
*   `{CHAIN}`: The PEM-encoded Intermediate/Root Chain.

#### Example 1: Standard JSON Payload
Most modern APIs expect a JSON object with fields for the cert and key.
```json
{
  "data": {
    "certificate": "{CERT}",
    "private_key": "{KEY}",
    "serial": 12345
  }
}
```

#### Example 2: Flat JSON
```json
{
  "cert_pem": "{CERT}",
  "key_pem": "{KEY}",
  "chain_pem": "{CHAIN}"
}
```

## 3. Workflow
1.  **Configure**: Set up the service with the correct URL and Template.
2.  **Save**: The configuration is saved encrypted in `config.yaml`.
3.  **Renew**: When you click "Renew" (or on auto-renewal):
    *   The system reads the latest certificate files from disk.
    *   It substitutes `{CERT}` and `{KEY}` in your template with the actual file content.
    *   It sends the HTTP request to your defined URL.
4.  **Result**: 
    *   **Success (200-299)**: The system marks the renewal as successful.
    *   **Failure (300+)**: The system logs the error code and response body.

## 4. Troubleshooting
*   **"Template preparation failed"**: Check that your Body Template is valid text/JSON.
*   **"Webhook failed: 401"**: Check your `Authorization` header.
*   **"Webhook failed: 400"**: The target server rejected the format. Check if they expect `\n` characters to be escaped (the system handles standard string replacement, but ensure your JSON syntax is valid around the placeholders).
    *   *Tip*: The system automatically handles newlines inside the certificate string if you treat it as a JSON string value.
