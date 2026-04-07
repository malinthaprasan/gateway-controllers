.PHONY: generate-catalog validate-catalog

generate-catalog: ## Generate docs/README.md policy catalog from metadata.json files
	python3 scripts/generate-policy-catalog.py

validate-catalog: ## Verify docs/README.md is up to date (used in CI)
	python3 scripts/generate-policy-catalog.py --validate
