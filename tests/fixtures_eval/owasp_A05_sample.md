# A05:2025 Injection

## Overview

Injection vulnerabilities, including SQL injection and Cross-Site Scripting (XSS), occur when untrusted data is sent to an interpreter as part of a command or query.

## Description

Attackers supply malicious input that tricks the interpreter into executing unintended commands or accessing unauthorized data.

## How to prevent

Preventing injection requires keeping data separate from commands and queries. Use parameterized queries and safe APIs.

## Example attack scenarios

Scenario 1: An application uses untrusted data in the construction of the following vulnerable SQL call:
SELECT * FROM accounts WHERE custID='admin' OR '1'='1'
