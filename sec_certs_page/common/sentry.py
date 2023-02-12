from contextlib import contextmanager

from sentry_sdk import push_scope
from sentry_sdk.tracing import Span


class NoChildSpan(Span):
    def start_child(self, **kwargs):
        return super().start_child(sampled=False, **kwargs)


@contextmanager
def suppress_child_spans():
    with push_scope() as scope:
        scope.span = NoChildSpan()
        try:
            yield
        finally:
            pass
