FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /krakenkey \
    ./cmd/krakenkey

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /krakenkey /krakenkey
ENTRYPOINT ["/krakenkey"]
