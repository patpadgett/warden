# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **Warden**, please help us keep our users safe by reporting it privately.  

- **Email:** pat@patpadgett.com
- **GitHub:** https://github.com/patpadgett/warden - open a private issue and mark it as *Security*

We will acknowledge receipt of your report within 48 hours and aim to provide a fix or mitigation as quickly as possible.  

## Preferred Disclosure Timeline

- **Initial acknowledgment:** within 2 business days.
- **Patch development:** we will work to release a patch within a reasonable timeframe, typically no more than 2 weeks for critical issues.
- **Public disclosure:** after a fix is released, we will publicly disclose the vulnerability and the steps taken to resolve it.

## Security Best Practices

- Keep your deployment up‑to‑date with the latest releases.
- Use TLS for all external traffic and follow the TLS configuration guidelines in the docs.
- Restrict database file permissions to the `warden` system user.
- Monitor the Prometheus metrics for unusual activity.
