FROM --platform=$BUILDPLATFORM golang:1.26.4-bookworm@sha256:5d2b868674b57c9e48cdd39e891acce4196b6926ca6d11e9c270a8f85106203d AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /app/gohpts ./cmd/gohpts

FROM debian:bookworm-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3

RUN apt-get update && apt-get install -y --no-install-recommends bash iptables iproute2 procps iputils-ping dnsutils && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/gohpts /usr/local/bin/gohpts

ENTRYPOINT ["gohpts"]
