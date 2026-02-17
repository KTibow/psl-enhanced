Put all ephemeral data in a subdir of `data`.

Put all scripts at the top level.

Never make CLIs. Prefer using top level constants for important configuration instead.

It's 2026. Node runs TypeScript by default (it can even import with the syntax `./file.ts`). Node can include a `.env` via `--env-file=.env`.

Learnings from package.json: type module is already set. always use pnpm.
