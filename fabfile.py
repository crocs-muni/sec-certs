from fabric import task


def as_www_data(command, virtual=True):
    """
    Simply prefixes the `command` with
    sudo su www-data -s /bin/fish -c '`command`'
    """
    www_data_shell = [
        "sudo",
        "su",
        # "--login", # NOTE in login shell this c.cd("/path") won't work
        "www-data",
        "--shell",
        "/bin/fish",
        "--command",
    ]
    # NOTE: not a nice solution, but we need to source the virtual only after
    # we sudo as www-data
    if virtual:
        command = ["source", "/var/www/sec-certs/virt/bin/activate.fish", "&&"] + command
    joined_command = " ".join(command)
    www_data_shell.append(f'"{joined_command}"')
    return " ".join(www_data_shell)


@task
def ps(c):
    """Print running processes."""
    c.run("ps axuf")


@task
def pull(c):
    """Pull latest git (origin/page)."""
    with c.cd("/var/www/sec-certs"):
        c.run(as_www_data(["git", "pull", "origin", "page"], virtual=False))


@task
def tail_celery(c):
    """Tail the celery log."""
    c.run("tail -f /var/log/celery/certs.log")


@task
def reload_celery(c):
    """Reload the celery worker."""
    if c.run("test -f /run/celery/certs.pid"):
        resp = c.run("cat /run/celery/certs.pid")
        pid = resp.stdout.strip()
        if c.run(f"test -d /proc/{pid}"):
            print(f"Reloading celery {pid}")
            c.sudo(f"kill {pid}")
            print("Reloaded celery")
        else:
            print("Celery pidfile found but not running.")
    else:
        print("Celery pidfile not found")


@task
def tail_uwsgi(c):
    """Tail the uWSGI log."""
    c.sudo("tail -f /var/log/uwsgi/app/certs.log")


@task
def reload_uwsgi(c):
    """Reload the uWSGI master."""
    c.sudo("systemctl reload uwsgi")


@task
def tail_nginx(c):
    """Tail the nginx access log."""
    c.run("tail -f /var/log/nginx/access.log")


@task
def reload_nginx(c):
    """Reload nginx."""
    c.sudo("systemctl reload nginx")


@task
def update(c):
    """Update the sec-certs clone."""
    print("Updating...")
    with c.cd("/var/www/sec-certs/sec-certs"):
        c.run(as_www_data(["git", "pull", "--tags", "origin", "main"], virtual=False))


@task
def deploy(c):
    """Deploy the whole thing, does a reload-only deploy."""
    print("Pulling...")
    pull(c)
    print("Reloading celery...")
    reload_celery(c)
    print("Reloading uWSGI...")
    reload_uwsgi(c)
    ps(c)
    c.local("curl https://seccerts.org")


@task
def dump(c):
    """Dump MongoDB data and download them."""
    print("Dumping...")
    tmp_dir = c.run("mktemp -d").stdout.strip()
    try:
        with c.cd(tmp_dir):
            c.run("mongodump -d seccerts")
            c.run("tar --zstd -cf dump.tar.zst dump/")
            c.get(f"{tmp_dir}/dump.tar.zst", "dump.tar.zst")
    finally:
        c.run(f"rm -r '{tmp_dir}'")


@task
def release(c):
    version = c.local("sentry-cli releases propose-version", hide="both").stdout.strip()
    c.local(f"sentry-cli releases new {version}")
    c.local(f"sentry-cli releases finalize {version}")
    c.local(f"sentry-cli releases set-commits {version} --local")


@task
def restore(c):
    """Restore MongoDB data locally."""
    print("Restoring...")
    c.local("rm -rf dump/")
    c.local("tar --zstd -xf dump.tar.zst")
    c.local("mongorestore --nsInclude=seccerts.\\* --drop --maintainInsertionOrder")
