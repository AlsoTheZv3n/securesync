# SecureSync Frontend (Next.js 14)

This directory will hold the Next.js 14 App Router frontend.

## First-time setup (run once)

The Next.js scaffold must be generated interactively — we do not commit a
hand-written `package.json` because `create-next-app` configures dependencies,
ESLint, Tailwind, and the `src/` layout in one step.

```bash
cd frontend

# Initialize Next.js 14 + TypeScript + Tailwind + App Router + src dir
npx create-next-app@14 . \
  --typescript \
  --tailwind \
  --app \
  --src-dir \
  --eslint \
  --import-alias "@/*"

# Initialize shadcn/ui (use 'New York' style + 'Slate' base color when prompted)
npx shadcn@latest init

# Install runtime libs we know we need (per docs/tech-stack.md)
npm install \
  @tanstack/react-query@5 \
  recharts@2 \
  framer-motion@11 \
  react-hook-form@7 \
  zod@3 \
  next-auth@5 \
  lucide-react

# Install dev/test libs
npm install -D @playwright/test
npx playwright install --with-deps
```

Once `npx create-next-app` has run, **delete the auto-generated
`README.md`** in this folder (it overwrites this file) and rewrite it to
document the project-specific commands.

## Day-to-day commands

```bash
npm run dev       # http://localhost:3000
npm run build
npm run lint
npx playwright test
```

## Environment

Required variables (loaded automatically from the repo-root `.env.local`
or set via `frontend/.env.local`):

```
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=<openssl rand -hex 32>
```

## Style guardrails

See `../CLAUDE.md` and `../docs/design.md` — short version:

- App Router only (no `pages/`)
- shadcn/ui for all base components
- TanStack Query for all data fetching (no raw `fetch` in components)
- Server Components by default; opt into `"use client"` only when needed
- Strict TypeScript — no `any`
