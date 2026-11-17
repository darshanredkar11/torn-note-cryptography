# Torn Note Showcase

A public-facing Next.js showcase for the Torn Note research prototype and the proposed FIDO2 / WebAuthn integration direction.

## Local development

Requirements: Node.js 22 or newer and npm.

1. Change into this directory.
2. Run npm install.
3. Run npm run dev.
4. Open http://localhost:3000.

Validation commands: npm run typecheck and npm run build.

## Cult UI

This app uses the open-source Cult UI Halo Button and Halo Card components. Their source is included under components/ui/ and is owned by this project after copying from the Cult UI registry. Tailwind CSS v4 and shadcn theme tokens are configured in app/globals.css and components.json.

The component registry is configured as @cult-ui in components.json for future additions. Source updates should be reviewed before being copied into this app.

## Deployment

The app can be deployed as a Node web service on Render:

- Root directory: showcase
- Build command: npm install && npm run build
- Start command: npm start
- Runtime: Node 22 or newer

No environment variables are required for the static showcase.

## Product and security accuracy

The page describes the FIDO2 / WebAuthn + Torn Note combination as a proposed integration. The current Java research prototype does not contain a WebAuthn adapter, hardware-backed wallet custody, independent network services, or a durable production spend database.

The interactive supplier-change walkthrough is illustrative only. It does not invoke an authenticator, sign a message, verify a proof, or authorize a real operation.
