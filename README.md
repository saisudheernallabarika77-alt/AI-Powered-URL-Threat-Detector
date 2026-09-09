# AI-Powered URL Threat Detector

An AI-assisted URL threat intelligence console that helps users inspect suspicious links before opening them. The application analyzes URL structure, transport/security signals, redirects, and common attack patterns, then presents a clear risk explanation and VirusTotal-backed verdict when the integration is available.

## Features

- URL scanning without requiring an account
- Risk signal and human-readable threat explanation
- Detection heuristics for phishing, malware, redirects, XSS, SQL injection, and token-like URLs
- VirusTotal integration for vendor verdicts and analysis statistics
- Safe demo URLs and threat-demo examples for exploring the interface
- Responsive web interface built with React and Tailwind CSS
- Server-side API procedures implemented with tRPC
- Automated unit and integration tests for URL analysis and VirusTotal behavior
- Included technical documentation in `documentation-pdf/main.pdf`

## Technology

| Layer | Technology |
| --- | --- |
| Frontend | React, Vite, TypeScript, Tailwind CSS, shadcn/ui |
| API | Node.js, Express, tRPC |
| Validation | Zod |
| Data access | Drizzle ORM configuration |
| Testing | Vitest |
| Package manager | pnpm |

## Requirements

- Node.js 20 or newer
- pnpm
- A VirusTotal API key for live VirusTotal scans

## Local setup

1. Install dependencies:

   ```bash
   pnpm install
   ```

2. Create a local environment file and add the VirusTotal key:

   ```bash
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ```

   Keep environment files out of version control. The repository's `.gitignore` already excludes `.env` files.

3. Start the development server:

   ```bash
   pnpm dev
   ```

4. Open the local URL shown by the development server.

## Available scripts

| Command | Purpose |
| --- | --- |
| `pnpm dev` | Start the development server with watch mode |
| `pnpm check` | Run the TypeScript compiler without emitting files |
| `pnpm test` | Run the Vitest test suite |
| `pnpm build` | Build the Vite client and bundled production server |
| `pnpm start` | Start the production server from `dist` |
| `pnpm db:push` | Generate and apply Drizzle database migrations |
| `pnpm format` | Format the project with Prettier |

## VirusTotal behavior

The application is designed to remain usable when VirusTotal is unavailable or when no API key is configured. In that case, the server returns an unavailable integration result instead of exposing a credential or crashing the user interface. For complete live-integration testing, set `VIRUSTOTAL_API_KEY` in the test environment and run:

```bash
pnpm test
```

Tests that do not require external credentials can be run independently from the VirusTotal credential test.

## Project structure

```text
client/              React application and UI components
server/              Express/tRPC server and threat-analysis logic
shared/              Shared constants and types
drizzle/             Database schema and migration metadata
documentation-pdf/   Generated technical documentation
patches/             Package patches used by the project
```

## Security notes

- Do not commit `.env` files, API keys, tokens, or other secrets.
- VirusTotal requests are performed server-side so the API key is not exposed to the browser.
- This project is an educational URL-analysis tool and is not a replacement for enterprise security tooling or a complete malware sandbox.
- Treat every scanned URL as untrusted input and avoid opening suspicious links directly.

## License

No license has been specified in the original project. Add a license file before distributing the project publicly under a particular license.
