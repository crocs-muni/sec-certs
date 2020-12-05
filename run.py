#!/usr/bin/env python3
from sec_certs import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
