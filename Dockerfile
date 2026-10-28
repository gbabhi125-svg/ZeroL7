FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/proxy ./cmd/proxy
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mockbackend ./cmd/mockbackend

FROM alpine:3.19 AS runtime
RUN apk add --no-cache ca-certificates && \
    addgroup -S zerol7 && adduser -S zerol7 -G zerol7
WORKDIR /app
COPY --from=build /out/proxy /app/proxy
COPY config/config.yaml /app/config/config.yaml
USER zerol7
EXPOSE 8080 9090
ENTRYPOINT ["/app/proxy"]
CMD ["-config", "/app/config/config.yaml"]
