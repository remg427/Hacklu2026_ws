# 1. Write the bundle (your repo)
cd /Users/remi/github/Hacklu2026_ws
opentide generate explorer          # -> .opentide/exports/explorer.bundle.json + explorer.search.json

# 2. Get the viewer
git clone --depth 1 https://github.com/OpenTideHQ/explorer.git /tmp/ot-explorer
cd /tmp/ot-explorer
pnpm install --frozen-lockfile      # 9.8s

# 3. Copy exports in + codegen, then build WITHOUT the typecheck
node bin/build.mjs build \
  --exports-dir /Users/remi/github/Hacklu2026_ws/.opentide/exports \
  --schemas-dir /Users/remi/github/Hacklu2026_ws/.opentide/schemas \
  --output /tmp/ot-site --base-path ""     # fails at tsrs, but copies data + runs codegen
NEXT_PUBLIC_BASE_PATH="" pnpm exec next build

# 4. Serve
npx serve -l 4173 out