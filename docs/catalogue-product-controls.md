# Catalogue product chooser and compact controls

Isolated branch: `codex/catalogue-product-controls`, based on `d28c8bb28defd00c8f4d757c931d2d4402f04866`. Existing working trees and the recently merged monitoring work remain intact. Open PRs 92/93 concern public advisory coverage; shared-file integration should preserve the existing catalogue scope controls and monitoring release classifier.

## Changes

- Technology cards open a searchable product chooser directly from “Choose the exact product” or an unresolved product name. Product scan status opens the same dialog. It shows every available returned identity, a filtered count, and whether the directory search is complete or partial. Selection requires an explicit confirmation.
- Windows Server OS previously searched its display name literally, which can return no directory matches. `directorySearch` in `product-identity.js` searches “Microsoft Windows Server” and filters results to non-deprecated Microsoft Windows Server OS families. Maria DB searches “MariaDB”. Choices come from NVD data, not a hardcoded release list. No product is chosen automatically from the Windows Server group.
- The authenticated, scope-checked `POST /v1/cvie/products/:id/identity-options` route queues a corrected lookup on demand using the existing provider budget and scheduler. Reopening an already queued or completed lookup does not create a second job. Explicit retries have a one-minute cooldown. The chooser attempts up to three directory pages within the existing global request budget, targeting only the requested product and never starting historical CVE scans. Remaining pagination resumes through the scheduler; partial results remain selectable. Choosing an identity revokes the old directory lease to prevent a late page from overwriting it.
- A small × beside the technology name removes that selection through the existing revision-protected catalogue save. It appears on hover or keyboard focus and remains visible on touch devices. A failed save leaves the saved catalogue and cards intact. Built-ins are unchecked; custom products are retained but disabled so they can be selected again. Inventory/watchlist subscriptions and shared history remain separate.
- “My monitored technologies” is limited to 1120px, grouped into the four existing categories, with compact checkbox rows, adjacent custom-product controls and a collapsible custom-product form. The existing sidebar, navigation and colour scheme are preserved.

## Validation and release

Backend tests cover Windows Server filtering, pagination, unchanged requests, identity validation, persistence and account isolation. Chromium tests cover the direct chooser, search, identity confirmation, keyboard-visible ×, failed removal, successful built-in/custom removal, persistence and responsive layouts. Existing catalogue, explorer and customer report regressions are run before release.

The production preflight reads D1 without writes and separately verifies the public NVD Windows Server lookup. The narrow catalogue code-only release classification includes these identity changes, skips migrations/bootstrap/cache resets, and retains the existing monitoring classification. No schema or production configuration change is required. No customer catalogue is changed by release verification.

The directory can be rate limited or unavailable. The dialog reports lookup state and offers an explicit retry; it does not claim a partial list is complete. Existing safeguards cap directory exploration at 10,000 entries or 500 product families. Selecting an OS family does not establish that an installation is secure or select its installed edition/build.

Live NVD verification on 2026-11-01 completed all 1,256 directory entries across three pages and returned 14 selectable families: Windows Server 2003, 2008, 2012, 2016, 2019, 2022, 2022 23H2, 2025, and releases 1709, 1803, 1903, 1909, 2004 and 20H2. This is a source-directory family list, not a claim that legacy releases remain supported. The D1 preflight wrote zero rows. Local validation passed 26 backend test files, 116 Python tests, explorer/customer DOM suites and both catalogue/customer Chromium suites.
