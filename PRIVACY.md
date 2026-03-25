# Privacy Policy

**Last updated:** March 24, 2026

## The short version

Exemplar is a local-only tool. Your data stays on your machine. We don't collect it, transmit it, or have access to it.

## What Exemplar Is

Exemplar is an open-source CLI and MCP tool for governed code review. It runs entirely on your computer — there is no cloud service, no account system, and no server infrastructure. Pull request diffs are analyzed locally through a multi-stage pipeline (security, correctness, style, architecture) that produces verified review reports.

## Data We Collect

None. Exemplar does not collect, transmit, store, or process any user data on external servers. All data remains on your local filesystem under your control.

## Data You Create

When you use Exemplar, you create local review artifacts including analysis results, trust scores, audit trails, and chronicle events. This data is stored in your local project directory.

This data never leaves your machine unless you explicitly copy, share, or publish it yourself.

## Third-Party Services

Exemplar does not communicate with any third-party services for its core operation. It does not phone home, check for updates, or transmit telemetry.

If you configure optional LLM providers for AI-assisted review, those API calls are made using your own API key and are governed by that provider's terms. Exemplar does not intermediate, log, or cache these requests beyond local analysis artifacts.

## MCP Server Context

When Exemplar is used as an MCP server within Claude Code or Claude Desktop, tool responses are returned to the host application. This content is processed by the host according to its own privacy policy (e.g., the [Anthropic Privacy Policy](https://www.anthropic.com/privacy)). Exemplar has no visibility into or control over what happens after tool responses are returned to the host.

## Analytics and Tracking

The website (exemplar.tools) does not use cookies, analytics, tracking pixels, or third-party scripts.

## Data Retention and Deletion

All data is local. Delete the project's review artifacts and everything is gone. There is nothing to request from us because we don't have anything.

## Children's Privacy

Exemplar does not collect personal information from anyone, including children under 13.

## Changes to This Policy

If Exemplar ever adds cloud features or data collection, this policy will be updated before those features ship. Local-only is an architectural principle, not an accident.

## Contact

- Email: jmc@cageandmirror.com
- Source: [github.com/jmcentire/exemplar](https://github.com/jmcentire/exemplar)
- Web: [exemplar.tools/privacy](https://exemplar.tools/privacy)
