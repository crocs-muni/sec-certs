from dash import Dash as OriginalDash
from flask import render_template


# Subclass Dash in order to put our template around it.
# Changing it via "dash.index_string" is insufficient because we need to
# render it during a request (it needs a request context).
class Dash(OriginalDash):

    def interpolate_index(
        self,
        metas="",
        title="",
        css="",
        config="",
        scripts="",
        app_entry="",
        favicon="",
        renderer="",
    ):
        return render_template(
            "dash.html.jinja2",
            metas=metas,
            title=title,
            css=css,
            config=config,
            scripts=scripts,
            app_entry=app_entry,
            favicon=favicon,
            renderer=renderer,
        )
