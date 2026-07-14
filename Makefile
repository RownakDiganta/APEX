# Makefile — convenience targets for the APEX knowledge pipeline and test suite.
#
# Dependencies and the Python environment are managed by `uv` (see README.md).
# All commands run through `uv run`, which uses the project's .venv (created by
# `uv sync --all-groups`) and the interpreter pinned in .python-version.

KNOWLEDGE_ROOT := ./knowledge

.PHONY: compile-knowledge verify-knowledge test lint typecheck help

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-25s %s\n", $$1, $$2}'

compile-knowledge:  ## Compile all knowledge families into compact JSONL outputs
	uv run python -m apex_host.knowledge.compiler.compile_knowledge \
	    --knowledge-root $(KNOWLEDGE_ROOT) \
	    --strict --verbose

verify-knowledge:  ## Verify all 9 required compiled outputs are valid
	uv run python -m apex_host.knowledge.compiler.verify_compiled \
	    --knowledge-root $(KNOWLEDGE_ROOT)

test:  ## Run the full test suite
	uv run pytest -q

lint:  ## Run Ruff
	uv run ruff check .

typecheck:  ## Run mypy over memfabric + apex_host
	uv run mypy
