![](sec_certs_page/static/img/logo.svg)

# seccerts.org page

This branch contains a [Flask](https://palletsprojects.com/p/flask/) app that is available
at [seccerts.org](https://seccerts.org) and can be used to serve a page with the data locally.

## Usage

The page uses [MongoDB](https://www.mongodb.com/) as a backend for the certificate data, as well as 
[dramatiq](https://dramatiq.io/) (using [redis](https://redis.io/) as a backend) as a
task queue.

1. Install the requirements, it is recommended to do so into a newly created Python virtual environment.
   The minimal required Python version is 3.8.
   ```shell
   python -m venv virt                # Creates the virtualenv.
   . virt/bin/activate                # Activates it.
   pip install -e .                   # Installs the web
   ```
2. Create the `instance` directory.
   ```shell
   mkdir instance 
   ```
3. Create a `config.py` file in the `instance` directory, based on the [`example.config.py`](config/example.config.py) file in the repository.
4. Create a `settings.yaml` file in the `instance` directory, based on the [`example.settings.yaml`](config/example.settings.yaml) file in the repository.
   It is quite important to keep the progress bar setting disabled to not pollute the logs of the webapp.
5. Start MongoDB and Redis.
6. Run the Flask app (in production you should likely use [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) 
   and [nginx](https://nginx.org/en/), see the [example config file](config/example.uwsgi.ini)).
   ```shell
   flask -A sec_certs_page run
   ```
7. Run the dramatiq and periodiq workers.
   ```shell
   dramatiq sec_certs_page:broker -p 2 -t 1
   periodiq sec_certs_page:broker -p 2 -t 1
   ```

### Deployment
Production deployment should use [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) and [nginx](https://nginx.org/en/).

## Docker

There is a rudimentary Dockerfile available that currently lacks MongoDB and redis,
and the task queue setup.