FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /out/tasky . \
 && go build -trimpath -ldflags="-s -w" -o /out/check-panel-marker-access ./cmd/check-panel-marker-access \
 && go build -trimpath -ldflags="-s -w" -o /out/backup-reader ./cmd/backup-reader

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS release
WORKDIR /app
COPY --from=build --chmod=0555 /out/tasky /out/check-panel-marker-access /out/backup-reader /app/
COPY --from=build /src/assets /app/assets
COPY --chmod=0444 wizexercise.txt /app/wizexercise.txt
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD ["/bin/busybox", "wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/app/tasky"]
