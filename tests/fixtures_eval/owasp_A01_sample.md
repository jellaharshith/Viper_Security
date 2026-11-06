# A01:2025 Broken Access Control

## Overview

Broken Access Control occurs when users can act outside of their intended permissions, leading to unauthorized information disclosure, modification, or destruction of data.

## Description

Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized data disclosure or privilege escalation.

## How to prevent

Access control is only effective when enforced in trusted server-side code or serverless API, where the attacker cannot modify the access control check or metadata.

## Example attack scenarios

Scenario 1: An attacker forces browsing to target URLs without proper authorization checks, accessing administrative functions.
