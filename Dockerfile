FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS builder

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
