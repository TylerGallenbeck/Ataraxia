# Ataraxia Security Agents - Claude Code Integration

This repository contains a collection of security auditing agents designed for Claude Code integration.

## Quick Start

Load agents directly by referencing their markdown files:

```bash
# Load the Python security agent
@agents/python/python-security-agent.md

# Then analyze code
Please review this Python code for security issues: [paste code]
```

## Available Agents

| Language   | Agent Name   | Specialization | File Path |
|------------|--------------|----------------|-----------|
| Python     | SentinelPy   | Security audit | `agents/python/python-security-agent.md` |
| Go         | SentinelGo   | Security audit | `agents/go/go-security-agent.md` |
| Rust       | IronGuard    | Security audit | `agents/rust/rust-security-agent.md` |
| JavaScript | GuardianJS   | Security audit | `agents/javascript/javascript-security-agent.md` |
| TypeScript | TypeGuard    | Security audit | `agents/typescript/typescript-security-agent.md` |
| Ruby       | RubyShield   | Security audit | `agents/ruby/ruby-security-agent.md` |

## Agent Capabilities

Each agent provides:
- **Language-specific security analysis** - Tailored to each language's unique vulnerabilities
- **Detailed issue reporting** - Clear explanations with severity ratings
- **Secure code fixes** - Ready-to-use patches following best practices
- **Tool recommendations** - Suggests appropriate security tools and libraries
- **Compliance guidance** - Follows industry security standards

## Usage Patterns

Load specific agents for targeted analysis:

```bash
# Security-focused review
Load @agents/python/python-security-agent.md and review this authentication module

# Multi-language analysis
Load @agents/go/go-security-agent.md
Load @agents/python/python-security-agent.md
```

## Best Practices

1. **Run audits regularly** - Integrate into your development workflow
2. **Address high-severity issues first** - Prioritize by security impact
3. **Use language-specific agents** - Each agent understands unique language risks
4. **Combine with automated tools** - Agents complement static analysis tools
5. **Review agent recommendations** - Understand the security rationale behind suggestions

## Example Usage

```bash
# Get recommendations for secure implementations  
Load @agents/go/go-security-agent.md
How should I implement JWT authentication securely in Go?

# Load specific agent for code review
Load @agents/python/python-security-agent.md
Please review this authentication module for security issues
```

## Extending the System

To add new agents or modify existing ones:
1. Follow the established agent format in existing `.md` files
2. Test with your development workflow

Each agent is self-contained and can be used independently or as part of the full security analysis suite.