# A05:2025 Injection ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## Background.

Injection is one of the most tested categories, including SQL injection and cross-site scripting.

## Score table.

<table><tr><td>CWEs Mapped</td></tr></table>

## Description.

An injection vulnerability lets untrusted input reach an interpreter. See the [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/).

## How to prevent.

* Use a **parameterized** API.
* Validate input on the server.

## Example attack scenarios.

**Scenario #1:** A vulnerable SQL call:

```
# this comment-looking line must not start a new section
## nor must this one
String query = "SELECT * FROM accounts WHERE custID='" + id + "'";
```

## References

* Should not be indexed.

## List of Mapped CWEs

* CWE-79
