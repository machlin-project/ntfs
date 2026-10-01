BUILD ?= .build
.PHONY: build test format check-style fskit
build:
	python3 scripts/build.py $(BUILD)
test: build
	python3 scripts/test.py $(BUILD)
format:
	python3 scripts/format.py
check-style:
	python3 scripts/format.py --check
fskit:
	python3 scripts/build_fskit.py
