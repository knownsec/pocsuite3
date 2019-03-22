SRC_DIR = pocsuite3
MAKE = make


.PHONY: prebuildclean install build pypimeta pypi buildupload test flake8 clean


prebuildclean:
	@+python -c "import shutil; shutil.rmtree('build', True)"
	@+python -c "import shutil; shutil.rmtree('dist', True)"
	@+python -c "import shutil; shutil.rmtree('pocsuite3.egg-info', True)"

install:
	python3 setup.py install

build:
	@make prebuildclean
	python3 setup.py sdist --formats=zip bdist_wheel
	#python3 setup.py bdist_wininst

pypimeta:
	twine register

pypi:
	twine upload dist/*

buildupload:
	@make build
	#@make pypimeta
	@make pypi

test:
	tox --skip-missing-interpreters

flake8:
	@+flake8 --max-line-length=120 --exclude .asv,.tox,pocsuite3/thirdparty -j 8 --count --statistics --exit-zero pocsuite3 --ignore E501,F401,F403,W503,W605

clean:
	rm -rf *.egg-info dist build .tox
	find $(SRC_DIR) tests -type f -name '*.pyc' -delete
