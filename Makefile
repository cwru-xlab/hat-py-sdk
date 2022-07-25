# Reference: https://dev.to/luscasleo/creating-and-publishing-a-python-lib-with-poetry-and-git-11bp
version: # Usage: make version v=<patch, minor, major, prerelease, etc.>
	@poetry version $(v)
	@git add pyproject.toml
	@git commit -m "v$$(poetry version -s)"
	@git tag v$$(poetry version -s)
	@git push
	@git push --tags
	@poetry version
