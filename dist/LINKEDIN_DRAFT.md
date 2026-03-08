Finally managed to complete my SSL automation project.

I’ve been working on this tool, CertAutomator, to handle the certificate renewals for my lab. It started because I was tired of manually uploading files to Proxmox and TrueNAS, ClearPass, etc every few months, and I wanted a cleaner solution than writing bash scripts for everything.

It’s reached v1.1.0 now and functions as a proper orchestration engine. It runs in Docker, picks up a wildcard cert or individual cert for different services, and pushes it to all my local services automatically. I also spent some time hardening it for actual production use. It runs as a non-root user, has encrypted storage for credentials, and runs on a Gunicorn server instead of just Flask.

It was built as a hobby project, but it's designed to scale if you need to manage certificates across a lot of internal servers.

The code is open source on GitHub if anyone wants to check it out or use it.

https://github.com/lokesh-sg/cert-automator

#python #automation #devops #opensource #networksecurity #certificates #ssl #pki
