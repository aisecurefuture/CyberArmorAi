# syntax=docker/dockerfile:1.7
# Two-stage build: mkdocs-material builds static HTML, nginx serves it.

FROM squidfunk/mkdocs-material:latest AS builder
WORKDIR /docs
COPY mkdocs.yml ./
COPY docs ./docs
RUN mkdocs build --strict

FROM nginx:alpine AS runner
COPY --from=builder /docs/site /usr/share/nginx/html
EXPOSE 80
