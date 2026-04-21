# -------------------------------------------------------
# Example Dockerfile with intentionally hardcoded secrets
# FOR TESTING SECRET SCANNERS ONLY (dummy values)
# -------------------------------------------------------

FROM ubuntu:22.04

LABEL maintainer="security-test@example.com"
ENV DEBIAN_FRONTEND=noninteractive

# ---- Hardcoded AWS credentials ----
ENV AWS_ACCESS_KEY_ID=AKIA7QWERTYUIOPZXCV
ENV AWS_SECRET_ACCESS_KEY=K9sdf8s7df98s7df9s8df7s9df87s9df87s9df87s9df
ENV AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEJr//////////wEaCXVzLWVhc3QtMSJIMEYCIQDdummyhighentropyTOKENEXAMPLE1234567890abcdEfGhIjKlMnOpQrStUvWxYz0987654321

# ---- Hardcoded database credentials ----
ENV DB_USERNAME=admin_user
ENV DB_PASSWORD=P@55w0rd!X9vTq3LmZr8YkN2wB6DfHsJpQ1cE7uA4iR0oM

# ---- Hardcoded generic API token ----
ENV API_TOKEN=ghp_A1b2C3d4E5f6G7h8I9j0KLMNOPQRSTUVWXYZabcd

# ---- Hardcoded private key (dummy but realistic format) ----
RUN mkdir -p /root/.ssh && \
    echo "-----BEGIN OPENSSH PRIVATE KEY-----" > /root/.ssh/id_rsa && \
    echo "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn" >> /root/.ssh/id_rsa && \
    echo "NhAAAAAwEAAQAAAIEA0dummyHIGHENTROPYSTRINGkjsdhf9823y4r9823y4r9823y4r98" >> /root/.ssh/id_rsa && \
    echo "asdf987asdf987asdf987asdf987asdf987asdf987asdf987asdf987asdf987asdf98" >> /root/.ssh/id_rsa && \
    echo "-----END OPENSSH PRIVATE KEY-----" >> /root/.ssh/id_rsa && \
    chmod 600 /root/.ssh/id_rsa

# ---- Hardcoded SSH public key ----
RUN echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7dummyHIGHENTROPYKEYSTRING1234567890abcdefghijklmnopqrstuvwxyz user@example.com" \
    > /root/.ssh/authorized_keys

# ---- Hardcoded .env file ----
RUN echo "SECRET_KEY=django-insecure-4f9d8f7s9df87s9df87s9df87s9df87s9df87s9df87s9df" > /app.env && \
    echo "JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummyPayloadSignatureExample0987654321" >> /app.env

# ---- Hardcoded config file with credentials ----
RUN mkdir -p /opt/app && \
    echo '{ \
      "username": "service_account", \
      "password": "Sup3rS3cr3tP@ssw0rd!0987654321asdfghjkl", \
      "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE", \
      "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
    }' > /opt/app/config.json

CMD ["bash"]