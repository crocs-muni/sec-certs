#!/usr/bin/env python
from flask_frozen import Freezer
from sec_certs import create_app

if __name__ == "__main__":
    app = create_app()
    freezer = Freezer(app)
    @freezer.register_generator
    def cc_entries():
        for i in range(1, 112):
            yield "cc.index", {"page": i}

    @freezer.register_generator
    def fips_entries():
        for i in range(1, 94):
            yield "fips.index", {"page": i}
    freezer.freeze()
