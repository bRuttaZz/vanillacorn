
help:	## Show all Makefile targets.
	@echo "Vanillacorn: Makefile targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[33m%-30s\033[0m %s\n", $$1, $$2}'

.required-files: vanillacorn.py pyproject.toml

version: .required-files ## App version
	@hatch version

build:	.required-files clean ## Build package
	@hatch build

publish: dist ## Publish build
	@twine upload dist/*

clean: ## Clean
	rm -rf dist
