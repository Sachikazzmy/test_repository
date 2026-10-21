FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY internal ./internal
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/banner-server ./cmd/server

FROM alpine:3.23
WORKDIR /app
COPY --from=build /out/banner-server /app/banner-server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/banner-server"]
