FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY cmd ./cmd
COPY rules ./rules
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/banner-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/banner-client ./cmd/client

FROM alpine:3.23 AS runtime
WORKDIR /app
USER 65532:65532

FROM runtime AS client
COPY --from=build /out/banner-client /app/banner-client
ENTRYPOINT ["/app/banner-client"]

FROM runtime AS server
COPY --from=build /out/banner-server /app/banner-server
COPY rules/rules.json /app/rules/rules.json
ENV BANNER_RULES_PATH=/app/rules/rules.json
EXPOSE 8080
ENTRYPOINT ["/app/banner-server"]
