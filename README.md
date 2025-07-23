Project Overview

This is a cloud-hosted secure login system built using Flask, deployed on AWS EC2, and protected against SQL injection attacks using a double-layer security protocol. 
It uses AES-256 encryption to store sensitive credentials and implements a capability code mechanism to gatekeep access.

✅ AES-256 password encryption using PyCryptodome  
✅ Capability code mechanism to protect signup/login  
✅ Parameterized queries to prevent SQL injection  
✅ Keyword-based filter (2nd layer SQLi protection)  
✅ Flask app hosted on AWS EC2 with SQLite  
✅ Web interface for Signup and Login

Security Highlights

Layer 1: Parameterized SQL queries to block injections  
Layer 2: Input filter for SQL keywords like `DROP`, `OR 1=1`, `--`, etc.  
AES-256 Encryption: Passwords are never stored in plaintext  
Capability Code: Only users with a secret code (e.g., `SECURE123`) can register or log in

to run: http://65.0.124.125//signup
        http://65.0.124.125//login

Use these test cases:
zarawar / MySecret123 / SECURE123 → login success
zarawar / 123' OR 1=1 -- / SECURE123 → blocked by SQLi filter
wronguser / anypass / WRONGCODE → invalid capability code

Deployed using:

Amazon EC2 (Amazon Linux 2023)
Public IP accessible from browser
Port 80 open via security group
