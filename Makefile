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

.PHONY: all clean install

all: ${BIN_DIR}/${TSSH}

${BIN_DIR}/${TSSH}: $(wildcard ./cmd/tssh/*.go ./*.go)
	go build -o ${BIN_DIR}/ ./cmd/tssh

clean:
	-rm -f ${BIN_DIR}/tssh{,.exe}

install: all
	mkdir -p ${DESTDIR}${BIN_DST}
	cp ${BIN_DIR}/tssh ${DESTDIR}${BIN_DST}/
