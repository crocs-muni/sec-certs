![](sec_certs_page/static/img/logo.svg)

# seccerts.org page

This branch contains a [Flask](https://palletsprojects.com/p/flask/) app that is available
at [sec-certs.org](https://sec-certs.org) and can be used to serve a page with the data locally.

**This web is meant to work in a HEAD-to-HEAD fashion with the main branch of the repository.**
I.e. we only really run the web with the head of the `page` branch together with the sec-certs
tool from the head of the `main` branch. You can do this easily using editable installs.
The easiest way to do that is to clone the repository twice, as described below.

## Usage

The page uses [MongoDB](https://www.mongodb.com/) as a backend for the certificate data, as well as
[dramatiq](https://dramatiq.io/) (using [Redis](https://redis.io/) as a backend) as a
task queue.

1. Install the requirements, it is recommended to do so into a newly created Python virtual environment.
   The minimal required Python version is 3.10.
   ```shell
   git clone -b page https://github.com/crocs-muni/sec-certs page
   git clone -b main https://github.com/crocs-muni/sec-certs tool

   python -m venv virt                 # Creates the virtualenv.
   . virt/bin/activate                 # Activates it. (Use .fish or .csh for those shells)
   pip install -U setuptools wheel pip # Always nice to have new versions, not some ancient ones.

   cd tool
   pip install -e .                    # Installs the tool

   cd ../page
   pip install -e .                    # Installs the web

   # The rest of the setup assumes you are in the "page" directory.
   ```
   Optionally, you can do the install using `uv`, the lockfile is provided.
2. Create the `instance` directory in the `page` directory.
   ```shell
   mkdir instance
   ```
3. Create a `config.py` file in the `instance` directory, based on the [`example.config.py`](config/example.config.py) file in the repository.
4. Create a `settings.yaml` file in the `instance` directory, based on the [`example.settings.yaml`](config/example.settings.yaml) file in the repository.
   It is quite important to keep the progress bar setting disabled to not pollute the logs of the webapp.
5. Start MongoDB and Redis.
6. When running locally, populate MongoDB - tasks `dump` and `restore` in [fabfile.py](./fabfile.py) or
   if you do not have admin access to the sec-certs.org server and someone provided you with a `dump`
   you can just use `mongorestore` (or consult the `restore` task).
7. For a fully working deployment, you need more results of the weekly processing that happens on the sec-certs.org
   server:
     - The CC files
     - The PP files
     - The FIPS files
     - The search index

   These should either be provided to you as archives (in which case simply extracting them to the instance directory is sufficient),
   or you need to run the weekly processing task to obtain them.
8. Run the Flask app (in production you should likely use [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/)
   and [nginx](https://nginx.org/en/), see the [example config file](config/example.uwsgi.ini)).
   ```shell
   flask -A sec_certs_page run
   ```
9. Run the dramatiq and periodiq workers, note that this is not necessary if you are not working with the task queue.
   ```shell
   dramatiq sec_certs_page:broker -p 2 -t 1
   periodiq sec_certs_page:broker -p 2 -t 1
   ```

### Deployment

Production deployment should use [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) and [nginx](https://nginx.org/en/).
Additionally, the fabfile can be used (likely with some modifications to suite your needs).

## Docker

There is a rudimentary Dockerfile available, it lacks the dramatiq and periodiq task queue runners.

## Development


### Tests

There are tests, run `pytest --cov sec_certs_page tests` to run them. They rely on having a MongoDB
server binary that is then temporarily started for the tests.

### Code style

There is [`pre-commit`](https://pre-commit.com/) setup. Please use it while contributing to this branch. You may ignore
some ever-present warnings by running `git commit -n`. **Black** is used for code formatting and **isort** for import sorting.

