BIN_DIR := ./bin
BIN_DST := /usr/bin

ifdef GOOS
	ifeq (${GOOS}, windows)
		WIN_TARGET := True
	endif
else
	ifeq (${OS}, Windows_NT)
		WIN_TARGET := True
	endif
endif

ifdef WIN_TARGET
	TSSH := tssh.exe
else
	TSSH := tssh
endif

GO_TEST := ${shell basename `which gotest 2>/dev/null` 2>/dev/null || echo go test}

.PHONY: all clean test install

all: ${BIN_DIR}/${TSSH}

${BIN_DIR}/${TSSH}: $(wildcard ./cmd/tssh/*.go ./tssh/*.go) go.mod go.sum
	go build -o ${BIN_DIR}/ ./cmd/tssh

clean:
	-rm -f ${BIN_DIR}/tssh ${BIN_DIR}/tssh.exe

test:
	${GO_TEST} -v -count=1 ./tssh

install: all
	mkdir -p ${DESTDIR}${BIN_DST}
	cp ${BIN_DIR}/tssh ${DESTDIR}${BIN_DST}/
