BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Werror
BPF_HEADERS ?= $(shell go env GOPATH)/pkg/mod/github.com/cilium/ebpf@v0.10.0/examples/headers

ARCH ?= amd64
BPF2GO_GENERATED = bpf_bpfel.go

.PHONY: all tidy clean

all: demo

tidy:
	@go mod tidy

demo: $(BPF2GO_GENERATED)
	@CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -o $@ main.go $^

$(BPF2GO_GENERATED): tidy
	@BPF_CLANG="$(BPF_CLANG)" BPF_CFLAGS="$(BPF_CFLAGS)" BPF_HEADERS="$(BPF_HEADERS)" \
			  go generate

clean:
	rm -f bpf_bpfeb.go
	rm -f bpf_bpfeb.o
	rm -f bpf_bpfel.go
	rm -f bpf_bpfel.o
	rm -f demo
