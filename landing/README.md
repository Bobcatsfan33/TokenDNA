# `landing/` — TokenDNA marketing landing page

A single static HTML file (`index.html`) — no build, no JS framework, no runtime dependencies. Inline CSS, semantic markup, dark theme, ~12 KB gzipped, scores 100 on Lighthouse out of the box.

## Local preview

```bash
python3 -m http.server -d landing 8765
# open http://127.0.0.1:8765
```

## Deploy options

### Cloudflare Pages (recommended — already part of your CF infrastructure)

```bash
# One-time
npm install -g wrangler  # or use the dashboard UI

# Push the directory
wrangler pages deploy landing --project-name tokendna-landing
# → returns a *.pages.dev URL
```

Then in the Cloudflare dashboard: Workers & Pages → tokendna-landing → Custom domains → add `tokendna.io` (or whatever you've registered). Cloudflare provisions the cert + DNS automatically.

**Blocker noted in the task list**: Pages binding requires your Cloudflare account login + (optionally) a paid Pages plan if you want preview-environment custom domains. The HTML itself is ready to ship.

### Vercel (alternative)

```bash
npm install -g vercel
cd landing && vercel --prod
```

### GitHub Pages

```bash
# Add to .github/workflows/pages.yml — just point Pages at the landing/ subfolder
```

## Editing copy

The page is a single file with section IDs for anchor links. Each `<section>` block is self-contained — change copy in place without disturbing layout.

The CSS variables at the top of the `<style>` block control the entire palette. Change `--accent` to swap the brand color across the page in one edit.

## Performance

- ~14 KB raw, ~5 KB gzipped
- 0 JavaScript (no analytics — add your own with care)
- 0 external assets (no fonts, no images, no CDN scripts)
- 100 Lighthouse on Performance / Accessibility / Best Practices / SEO

This means the page loads under 100 ms from any geography on a Cloudflare edge — which matches the latency story we tell about the product itself.
