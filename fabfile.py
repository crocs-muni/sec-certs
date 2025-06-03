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
        command = ["source", "/var/www/sec-certs/virt11/bin/activate.fish", "&&"] + command
    joined_command = " ".join(command)
    www_data_shell.append(f'"{joined_command}"')
    return " ".join(www_data_shell)


def check_deploy(c):
    resp = c.local("curl https://sec-certs.org/admin/candeploy").stdout.strip()
    print("Can deploy?", resp)
    return resp == "OK"


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
def tail_dramatiq(c):
    """Tail the dramatiq log."""
    c.run("tail -f /var/log/dramatiq/certs.log")


@task
def reload_dramatiq(c):
    """Reload the dramatiq worker."""
    if c.run("test -f /run/uwsgi/app/certs/dramatiq.pid"):
        resp = c.run("cat /run/uwsgi/app/certs/dramatiq.pid")
        pid = resp.stdout.strip()
        if c.run(f"test -d /proc/{pid}"):
            print(f"Reloading dramatiq {pid}")
            c.sudo(f"kill {pid}")
            print("Reloaded dramatiq")
        else:
            print("Dramatiq pidfile found but not running.")
    else:
        print("Dramatiq pidfile not found")


@task
def tail_uwsgi(c):
    """Tail the uWSGI log."""
    c.sudo("tail -f /var/log/uwsgi/app/certs.log")


@task
def reload_uwsgi(c):
    """Reload the uWSGI master."""
    if c.run("test -f /run/uwsgi/app/certs/pid"):
        resp = c.run("cat /run/uwsgi/app/certs/pid")
        pid = resp.stdout.strip()
        if c.run(f"test -d /proc/{pid}"):
            print(f"Reloading uWSGI {pid}.")
            c.sudo(f"kill -1 {pid}")
            print("Reloaded uWSGI.")
        else:
            print("uWSGI pidfile found but not running.")
    else:
        print("uWSGI pidfile not found.")


@task
def start_uwsgi(c):
    """Start the uWSGI master."""
    if c.run("test -f /run/uwsgi/app/certs/pid"):
        resp = c.run("cat /run/uwsgi/app/certs/pid")
        pid = resp.stdout.strip()
        if c.run(f"test -d /proc/{pid}"):
            print(f"uWSGI is already running (pid = {pid}).")
            return
        print("Old pidfile found, starting anyway.")
    c.sudo("cd /opt/uwsgi && ./uwsgi --ini /etc/uwsgi/apps-enabled/certs.ini --daemonize /var/log/uwsgi/app/certs.log")


@task
def stop_uwsgi(c):
    """Stop the uWSGI master."""
    if c.run("test -f /run/uwsgi/app/certs/pid"):
        resp = c.run("cat /run/uwsgi/app/certs/pid")
        pid = resp.stdout.strip()
        if c.run(f"test -d /proc/{pid}"):
            print(f"Stopping uWSGI {pid}.")
            c.sudo(f"kill -9 {pid}")
            print("Stopped uWSGI.")
        else:
            print("uWSGI pidfile found but not running.")
    else:
        print("uWSGI pidfile not found.")


@task
def tail_nginx(c):
    """Tail the nginx access log."""
    c.run("tail -f /var/log/nginx/access.log")


@task
def reload_nginx(c):
    """Reload nginx."""
    c.sudo("systemctl reload nginx")


@task
def start_nginx(c):
    """Start nginx."""
    c.sudo("systemctl start nginx")


@task
def stop_nginx(c):
    """Stop nginx."""
    c.sudo("systemctl stop nginx")


@task
def update(c):
    """Update the sec-certs clone."""
    print("Updating...")
    with c.cd("/var/www/sec-certs/sec-certs"):
        c.run(as_www_data(["git", "pull", "--tags", "origin", "main"], virtual=False))


@task
def deploy(c, force=False):
    """Deploy the whole thing, does a reload-only deploy."""
    if not check_deploy(c) and not force:
        print("Aborting deploy, tasks are running.")
        return
    print("Pulling...")
    pull(c)
    print("Reloading dramatiq...")
    reload_dramatiq(c)
    print("Reloading uWSGI (reloads periodiq)...")
    reload_uwsgi(c)
    ps(c)
    c.local("curl https://sec-certs.org")
    c.local(
        "curl https://sec-certs.org/cc/mergedsearch/?searchType=fulltext&q=something&cat=abcdefghijklmop&status=any&type=any"
    )
    c.local(
        "curl https://sec-certs.org/fips/mergedsearch/?searchType=fulltext&q=something&cat=abcdef&status=Any&type=any"
    )
    c.local(
        "curl https://sec-certs.org/pp/mergedsearch/?searchType=fulltext&q=something&cat=abcdefghijklmop&status=Any&type=any"
    )


@task
def release(c):
    """Create a new release on Sentry."""
    version = c.local("sentry-cli releases propose-version", hide="both").stdout.strip()
    c.local(f"sentry-cli releases new {version}")
    c.local(f"sentry-cli releases finalize {version}")
    c.local(f"sentry-cli releases set-commits {version} --local")


@task
def enable_maintenance(c):
    """Enable maintenannce mode for the site."""
    with c.cd("/var/www/sec-certs/"):
        c.run(as_www_data(["cp", "mntnc.html", "maintenance.html"], virtual=False))


@task
def disable_maintenance(c):
    """Disable maintenannce mode for the site."""
    with c.cd("/var/www/sec-certs/"):
        c.run(as_www_data(["rm", "maintenance.html"], virtual=False))


@task
def run_cc(c):
    """Run the CC update task."""
    print("Sending CC update task.")
    with c.cd("/var/www/sec-certs/sec-certs"):
        c.run(
            as_www_data(
                [
                    "env",
                    "INSTANCE_PATH=/data/flask/instance/",
                    "python",
                    "-c",
                    "'from sec_certs_page.cc.tasks import update_data; update_data.send()'",
                ],
                virtual=True,
            )
        )


@task
def run_fips(c):
    """Run the FIPS update task."""
    print("Sending FIPS update task.")
    with c.cd("/var/www/sec-certs/sec-certs"):
        c.run(
            as_www_data(
                [
                    "env",
                    "INSTANCE_PATH=/data/flask/instance/",
                    "python",
                    "-c",
                    "'from sec_certs_page.fips.tasks import update_data; update_data.send()'",
                ],
                virtual=True,
            )
        )


@task
def shell(c):
    """Get Flask shell."""
    with c.cd("/var/www/sec-certs/sec-certs"):
        c.run(
            as_www_data(
                ["env", "INSTANCE_PATH=/data/flask/instance/", "flask", "-A", "sec_certs_page", "shell"], virtual=True
            )
        )


@task
def dump(c):
    """Dump MongoDB data and download them."""
    tmp_dir = c.run("mktemp -d").stdout.strip()
    try:
        with c.cd(tmp_dir):
            print("Dumping...")
            c.run("mongodump -d seccerts")
            print("Archiving...")
            c.run("tar --zstd -cf dump.tar.zst dump/")
            print("Transmitting...")
            c.get(f"{tmp_dir}/dump.tar.zst", "dump.tar.zst")
            print("Done.")
    finally:
        c.run(f"rm -r '{tmp_dir}'")


@task
def restore(c):
    """Restore MongoDB data locally."""
    print("Restoring...")
    c.local("rm -rf dump/")
    c.local("tar --zstd -xf dump.tar.zst")
    c.local("mongorestore --nsInclude=seccerts.\\* --drop --maintainInsertionOrder")
