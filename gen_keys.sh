#!/bin/bash
#Generate keys and certificates

# Generating Private key for Trusted Machine(Authentication)
openssl genrsa -out privkeyServer.pem 512

# Generating Certificate for Trusted Machine
echo "Enter information for Trusted Machine Certificate"
openssl req -new -key privkeyServer.pem -x509 -days 365 -out certServer.pem

# Generating Private key for UnTrusted Machine (Authentication)
openssl genrsa -out privkeyClient.pem 512

# Generating Certificate for UnTrusted Machine
echo "Enter information for Untrusted Machine Certificate"
openssl req -new -key privkeyClient.pem -x509 -days 365 -out certClient.pem

# Generating Private key for Trusted Machine(Encryption)
openssl genrsa -out privkey_Server.pem 2048

# Generating Private key for Un-Trusted Machine(Encryption)
openssl genrsa -out privkey_Client.pem 2048
