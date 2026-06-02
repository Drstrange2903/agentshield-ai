# AgentShield AI

AgentShield AI is a Microsoft Build AI prototype for the **Security in the Agentic Future** theme. It acts as a prompt-injection firewall for AI agents by inspecting web content, agent instructions, and tool responses before an autonomous agent is allowed to act.

## Problem

Modern AI agents can browse websites, call tools, read documents, and trigger workflow automations. That makes them useful, but it also creates new attack surfaces:

- malicious pages can tell agents to ignore system instructions
- prompts can try to steal secrets or hidden policies
- tool responses can attempt unauthorized billing, admin, or data actions
- attackers can ask agents to hide actions from the user

## Solution

AgentShield scans incoming context before it reaches the agent execution layer. It assigns a risk score, explains detected threats, and recommends one of three actions:

- **Allow**: continue with normal monitoring
- **Review**: disable tools and request human approval
- **Block**: quarantine content and preserve an audit event

## Prototype Features

- Reusable explainable prompt-injection detection module
- Risk scoring from 0-100
- Demo scenarios for benign content, instruction override, secret theft, and tool abuse
- Recommended safe handling for each threat
- Dashboard explaining Microsoft stack fit
- Optional Azure OpenAI enhanced classifier through a local server-side proxy

## Microsoft AI Stack Fit

This prototype includes a local explainable firewall and an Azure-ready classifier path. The production design maps naturally to Microsoft technologies:

- **Azure AI Foundry**: host and orchestrate secured agents
- **Azure OpenAI**: classify ambiguous prompt-injection attempts
- **Azure AI Content Safety**: add policy and harmful-content screening
- **Azure AI Search**: retrieve approved policy, security, and audit guidance
- **Microsoft Defender**: surface agent security events to enterprise security teams
- **GitHub Advanced Security**: detect committed secrets and risky code paths
- **Power Automate**: require approval before sensitive tool execution

## How to Run

### Static Demo

Open `index.html` in a browser.

No build step or external dependency is required.

### Azure-Backed Demo

1. Copy `.env.example` to `.env`.
2. Fill in your Azure OpenAI endpoint, deployment name, API key, and API version.
3. Start the local server:

```bash
npm start
```

4. Open `http://localhost:4173`.
5. Enable **Azure enhanced scan** in the UI.

The Azure key is only read by `server.mjs`; it is never exposed in browser JavaScript and `.env` is ignored by Git.

## Test

```bash
npm test
```

Expected output:

```text
benign: Low risk (0)
prompt injection: High risk (75)
secret theft: Medium risk (35)
tool abuse: Medium risk (45)
```

## Hackathon Submission Notes

The repository should disclose any AI tools used during development and include setup instructions, team member details, and credits for open-source libraries or frameworks. This prototype uses plain HTML, CSS, and JavaScript.

## AI Tools Used

This prototype was built with assistance from Codex for scaffolding, code generation, and documentation. Human review, product direction, and final submission decisions remain with the team.
