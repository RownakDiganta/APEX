# Makefile — convenience targets for the APEX knowledge pipeline and test suite.
#
# All commands assume a virtual environment at .venv/ (created by `python -m venv .venv`).
# The PYTHON variable may be overridden: make test PYTHON=python3.12

PYTHON   := .venv/bin/python
KNOWLEDGE_ROOT := ./knowledge

.PHONY: compile-knowledge verify-knowledge test help

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-25s %s\n", $$1, $$2}'

compile-knowledge:  ## Compile all knowledge families into compact JSONL outputs
	$(PYTHON) -m apex_host.knowledge.compiler.compile_knowledge \
	    --knowledge-root $(KNOWLEDGE_ROOT) \
	    --strict --verbose

verify-knowledge:  ## Verify all 9 required compiled outputs are valid
	$(PYTHON) -m apex_host.knowledge.compiler.verify_compiled \
	    --knowledge-root $(KNOWLEDGE_ROOT)

test:  ## Run the full test suite
	$(PYTHON) -m pytest tests/ -q
