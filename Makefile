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

ifeq (${OS}, Windows_NT)
	RM := PowerShell -Command Remove-Item -Force
	GO_TEST := go test
else
	RM := rm -f
	GO_TEST := ${shell basename `which gotest 2>/dev/null` 2>/dev/null || echo go test}
endif

.PHONY: all clean test install

all: ${BIN_DIR}/${TSSH}

${BIN_DIR}/${TSSH}: $(wildcard ./cmd/tssh/*.go ./tssh/*.go) go.mod go.sum
	go build -o ${BIN_DIR}/ ./cmd/tssh

clean:
	$(foreach f, $(wildcard ${BIN_DIR}/*), $(RM) $(f);)

test:
	${GO_TEST} -v -count=1 ./tssh

install: all
ifdef WIN_TARGET
	@echo install target is not supported for Windows
else
	@mkdir -p ${DESTDIR}${BIN_DST}
	cp ${BIN_DIR}/tssh ${DESTDIR}${BIN_DST}/
endif
