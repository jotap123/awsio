rm -rf dist
python -m build
python -m twine upload dist/*

version=$(echo $(grep -m 1 version pyproject.toml | tr -s ' ' | tr -d '"' | tr -d "'" | cut -d' ' -f3))
echo $version
git tag $version
git push origin $version
