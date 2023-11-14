# ruff: noqa: F401
try:
    import catboost
    import optuna
    import plotly.express
    import setfit
    import sklearn
    import umap
except ImportError as e:
    print(e)
    print(
        f"Requirements for ML annotation of references not met. Please run `pip install sec-certs[nlp]` or install `pip install -r requirements/nlp_requirements.txt."
    )
