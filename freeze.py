#!/usr/bin/env python
from flask_frozen import Freezer
from sec_certs import create_app

if __name__ == "__main__":
	app = create_app()
	freezer = Freezer(app)
	freezer.freeze()