FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /server ./cmd/server
RUN go build -o /worker ./cmd/worker
RUN go build -o /ui ./cmd/ui

FROM alpine:latest

RUN apk add --no-cache sqlite ca-certificates

COPY --from=builder /server /server
COPY --from=builder /worker /worker
COPY --from=builder /ui /ui
COPY schema.sql /schema.sql

EXPOSE 8080 8081

CMD ["/server"]
