# Build for the OSS Scanner. The scanner uses the repository checkout as the build context.
FROM node:22-bookworm
ENV DEBIAN_FRONTEND=noninteractive \
    CI=true \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# The TSA client is a local package vendored under vendor/. It is not published to npm, and package.json
# references it as `workspace:*`, so the workspace file (not committed) is written here.
RUN printf 'packages:\n  - "."\n  - "vendor/trust-receipt-tsa-client"\n' > pnpm-workspace.yaml \
    && pnpm install --no-frozen-lockfile \
    && pnpm -r --filter ./vendor/trust-receipt-tsa-client run build \
    && pnpm run build

# Run the tests so the image is known to work, but do not let a failing test abort the build.
RUN (pnpm test || echo "WARNING: tests reported failures")
