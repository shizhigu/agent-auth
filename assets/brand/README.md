# Vouch brand assets

Logo, favicon, and Open Graph social card.

## Files

| File | Use |
|---|---|
| `logo-mark.svg` | Icon-only mark, **stroke uses `currentColor`** so callers can theme it via CSS. 24×24 viewBox. |
| `logo-mark-color.svg` | Icon-only with the brand color (`#5B6CFF`) baked in. Use when CSS theming isn't available (e.g. inline in a markdown screenshot). |
| `logo-full.svg` | Mark + wordmark, 180×48 viewBox. `currentColor` (use the colored variant for static placement). |
| `favicon.svg` | 32×32, filled background, optimized for tiny rendering. Drop into `public/favicon.svg` of any web app. |
| `og-image.svg` | 1200×630 social-share card. Used when the GitHub repo / docs site is shared on Twitter, Slack, Discord, etc. |

## Brand color

| Role | Hex |
|---|---|
| Primary (Vouch indigo) | `#5B6CFF` |
| Background dark | `#0B0D14` |
| Body dark | `#181A29` |
| Muted text | `#A8B0C8` |

## Logo concept

A hexagonal badge with a check-mark inside.

- **Hex** = "seal of vouching" — a guarantee, an attestation.
- **Check** = "verified" — the moment the SaaS hands the agent its scoped key.
- The check-mark shape subtly recalls the "V" initial.

The mark works at any size because it's stroke-based and monoline. At favicon scale (16–32 px) the filled background variant (`favicon.svg`) keeps it legible.

## Don't

- Don't recolor the badge to anything other than `#5B6CFF`, white, or black. The brand color is part of the identity.
- Don't fill the hex shape with solid color. The mark is a **stroke** — the negative space is intentional.
- Don't squash the wordmark non-uniformly. If you need a different aspect ratio, use the icon-only variant.

## Rendering PNG / JPG

GitHub social previews and some platforms (Twitter, LinkedIn) prefer PNG/JPG over SVG. Render once locally and commit the binaries (or wire a CI step):

```bash
# With sharp (Node):
npx --yes sharp-cli --input assets/brand/og-image.svg \
  --output assets/brand/og-image.png \
  --format png --width 1200

# Or with rsvg-convert (faster):
rsvg-convert -w 1200 -h 630 assets/brand/og-image.svg \
  -o assets/brand/og-image.png

# Favicon ICO (multi-size):
rsvg-convert -w 32 assets/brand/favicon.svg -o /tmp/favicon-32.png
rsvg-convert -w 16 assets/brand/favicon.svg -o /tmp/favicon-16.png
convert /tmp/favicon-{16,32}.png assets/brand/favicon.ico
```

Until those are committed, modern browsers + GitHub render the SVG fine.

## Files NOT generated yet

- `og-image.png` (1200×630) — generate via the command above, set in repo Settings → Social preview, and add the meta tag to `apps/docs`.
- `favicon.ico` — multi-size ICO; see above.

## License

Brand assets are © 2026 Agentic Flow LLC. The MIT license that covers the lib does **not** grant unlimited use of the logo or wordmark — see [trademark policy](#) (TODO when there's a real one) for the rules of the road. In short: don't fork the project and present the result as "Vouch" — make a new mark.
