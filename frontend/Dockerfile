FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000

RUN addgroup -S nextjs && adduser -S nextjs -G nextjs
COPY public ./public
COPY .next/standalone ./
COPY .next/static ./.next/static
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
