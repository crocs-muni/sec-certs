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
        "Requirements for ML annotation of references not met. Please install the 'nlp' extra, for example via: `pip install sec-certs[nlp]`."
    )
