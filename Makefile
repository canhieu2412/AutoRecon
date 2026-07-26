.PHONY: lint test tui-selftest test-web gui help

help:
	@echo "Auto Recon — make targets:"
	@echo "  make lint          bash -n + shellcheck + py_compile"
	@echo "  make test          lint + all headless functional tests"
	@echo "  make tui-selftest  reverse-shell file-transfer engine self-test"
	@echo "  make test-web      web backend + pages + shell-bridge test"
	@echo "  make gui           launch the web GUI on http://127.0.0.1:2412"

lint:
	@bash scripts/lint.sh

tui-selftest:
	@python3 modules/shell_tui.py --self-test

test-web:
	@python3 scripts/test_web.py

gui:
	@bash auto_recon.sh --gui

test: lint tui-selftest
	@bash scripts/test_phases.sh
	@python3 scripts/test_web.py
