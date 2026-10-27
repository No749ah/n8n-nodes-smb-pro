# n8n-nodes-smb-pro

n8n community node for SMB2/SMB3 shares with proper NTLMv2 support.

## Operations

- **List** – folder listing, optionally recursive and parallel; metadata comes straight from the directory query
- **Upload** / **Download** – binary file transfer
- **Delete**, **Move**, **Create Folder**, **Exists**

## List options

| Option | Default | Purpose |
|---|---|---|
| Folder Path | (empty) | Folder inside the share; empty = share root |
| Include File Stats | true | type, size, modified, created per entry (no extra requests) |
| Recursive | false | descend into subfolders (returns files only) |
| Max Depth | 0 | recursion limit, 0 = unlimited |
| Skip Inaccessible Folders | true | skip ACCESS_DENIED subfolders instead of failing |
| Concurrency | 4 | subfolders listed in parallel (global limit across all levels); 2–8 is plenty |

Output per entry: `name`, `path`, `type` (`file` / `folder`), `size`, `sizeHuman`,
`modified`, `created`. Skipped folders are returned with `accessDenied: true` and
`skipped: true`.

## Use as an AI Agent tool

The node declares `usableAsTool: true`, so it can be attached to the **Tool** port of an
AI Agent. n8n additionally requires community packages to be enabled for tool usage:

```
N8N_COMMUNITY_PACKAGES_ALLOW_TOOL_USAGE=true
```

Restart n8n after setting it. The node then appears in the agent's tool list and each
parameter (e.g. Folder Path) can be filled by the model via `$fromAI(...)`.

## Notes

- Uses NTLMv2 via `v9u-smb2`.
- Bundles a pure-JS MD4 implementation (RFC 1320) because OpenSSL 3 disables MD4,
  which NTLM requires. It is registered through a `crypto.createHash` patch.
- Errors are translated from NT status codes into readable messages
  (e.g. `STATUS_ACCESS_DENIED` → "Access denied – the account has no permission for this path").
- Retries only apply to transient errors.

## Build

```bash
npm install
npm run build      # tsc -> dist/
```

## Release

Publishing runs via GitHub Actions (`.github/workflows/publish.yml`) when a version tag is pushed.
It uses npm Trusted Publishing (OIDC), so no npm token is stored in the repository. The trusted publisher is configured on npmjs.com for `No749ah/n8n-nodes-smb-pro` with workflow `publish.yml`.

```bash
npm version patch   # or minor / major – bumps package.json and creates the tag
git push --follow-tags
```

The workflow checks that the tag matches `package.json`, builds and publishes (provenance is attached automatically).

## Changelog

- **1.3.0** – listing no longer opens every file: metadata comes from QUERY_DIRECTORY instead of a
  CREATE/CLOSE per entry (no antivirus scans or oplock breaks on the file server, far fewer requests);
  concurrency now limits parallel folder listings globally (default 4); `created` uses the real creation
  time instead of the change time
- **1.2.0** – node can be used as an AI Agent tool (`usableAsTool`)
- **1.1.3** – parallel stat lookups while listing (`Concurrency`), large speed-up on big folders
- **1.1.2** – recursive listing skips inaccessible folders, `Max Depth` option
- **1.1.1** – recursive listing combined with the MD4/OpenSSL 3 fix
- **1.0.1** – pure-JS MD4 so NTLM works on OpenSSL 3
- **1.0.0** – initial release

## Version

1.3.0
