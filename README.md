![](sec_certs_page/static/img/logo.svg)

# seccerts.org page

This branch contains a [Flask](https://palletsprojects.com/p/flask/) app that is available
at [seccerts.org](https://seccerts.org) and can be used to serve a page with the data locally.

## Usage

The page uses [MongoDB](https://www.mongodb.com/) as a backend for the certificate data, as well as 
[Celery](https://docs.celeryproject.org/en/master/index.html) (using either [redis](https://redis.io/) or RabbitMQ) as a
task queue.

1. Install the requirements, it is recommended to do so into a newly created Python virtual environment.
   The minimal required Python version is 3.8.
   ```shell
   python -m venv virt                # Creates the virtualenv.
   . virt/bin/activate                # Activates it.
   pip install -r requirements.txt    # Installs the requirements
   ```
   Note that this requires the pure python version of [python-frozendict](https://github.com/Marco-Sulla/python-frozendict).
2. Create the `instance` directory.
   ```shell
   mkdir instance 
   ```
3. Create a `config.py` file in the `instance` directory, based on the `example.config.py` file in the repository.
4. Create a `settings.yaml` file in the `instance` directory, based on the `example.settings.yaml` file in the repository.
   It is quite important to keep the progress bar setting disabled to not pollute the logs of the webapp.
5. Start MongoDB and Celery (with a proper backend like Redis). 
6. Run the Flask app (in production you should likely use [uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/) 
   and [nginx](https://nginx.org/en/)).
   ```shell
   env FLASK_APP=sec_certs FLASK_ENV=production flask run
   ```
   
### Data import

**This is outdated, the tool now does automatic updates using a periodic Celery task.**

The app uses MongoDB to store the certificate data extracted using the [sec-certs](https://github.com/crocs-muni/sec-certs)
tool, thus one has to import this JSON data into MongoDB and keep it up-to-date. To do so, the app
has specific commands behind the `flask cc,fips,pp` subcommands like:

```shell
$ env FLASK_APP=sec_certs_page FLASK_ENV=development flask --help
...
cc      Common Criteria commands.
fips    FIPS 140 commands.
pp      Protection Profile commands.
```
and
```shell
$ env FLASK_APP=sec_certs_page FLASK_ENV=development flask cc --help
...
Commands:
  create  Create the DB of CC certs.
  drop    Drop the DB of CC certs.
  import  Import CC certs.
  query   Query the MongoDB for certs.
  update  Update CC certs.
```

A typical use of these commands would be to first create the database and then import freshly generated certificates into it:
```shell
$ env FLASK_APP=sec_certs_page FLASK_ENV=development flask cc create
Creating...
Created
$ env FLASK_APP=sec_certs_page FLASK_ENV=development flask cc import cc_certificates.json
Loading certs...
Loaded
Inserting...
Inserted 123 certs
```

Afterwards, one can update the database of certificates with an updated dump from the tool
(beware that the ID which identifies a certificate/document is its name or ID number in case of FIPS):
```shell
$ env FLASK_APP=sec_certs_page FLASK_ENV=development flask cc update cc_certificates_new.json
```