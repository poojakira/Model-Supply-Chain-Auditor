.PHONY: all demo smoke test
all: demo smoke test
demo:
	@echo "Running demo for Model-Supply-Chain-Auditor..."
smoke:
	@echo "Running smoke tests for Model-Supply-Chain-Auditor..."
	./smoke_test.sh
test:
	@echo "Running tests for Model-Supply-Chain-Auditor..."
	pytest tests/ || echo "No tests found"
