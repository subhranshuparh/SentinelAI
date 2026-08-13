---
id: password_breaches
title: Password Reuse & k-Anonymity Breach Checks
tags: [password, identity, breach, k-anonymity, identity_guardian]
summary: Checking password compromise without revealing your password.
---

The Identity Guardian module tests passwords against over 900 million breached credentials using k-anonymity. Your browser hashes the password using SHA-1 and sends only the first 5 hex characters to the server. Matching occurs locally, ensuring your full password hash never leaves your machine.
