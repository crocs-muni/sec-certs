from contextlib import contextmanager

from dramatiq import Broker
from dramatiq.middleware import default_middleware
from sentry_sdk import Hub, new_scope
from sentry_sdk.integrations.dramatiq import DramatiqIntegration as OriginalDramatiqIntegration
from sentry_sdk.integrations.dramatiq import SentryMiddleware
from sentry_sdk.tracing import Span


class NoChildSpan(Span):
    def start_child(self, **kwargs):
        return super().start_child(sampled=False, **kwargs)


@contextmanager
def suppress_child_spans():
    with new_scope() as scope:
        scope.span = NoChildSpan()
        try:
            yield
        finally:
            pass


# Monkey patch the sentry-dramatiq monkey patch to not raise an exception
# when Sentry middleware is already passed into the broker init.
# This behavior conflicts with Flask-Melodramatiq which initializes a
# Stub broker first and then passes all the middlewares from it to the
# real broker.
def _patch_dramatiq_broker():
    original_broker__init__ = Broker.__init__

    def sentry_patched_broker__init__(self, *args, **kw):
        hub = Hub.current
        integration = hub.get_integration(OriginalDramatiqIntegration)

        try:
            middleware = kw.pop("middleware")
        except KeyError:
            # Unfortunately Broker and StubBroker allows middleware to be
            # passed in as positional arguments, whilst RabbitmqBroker and
            # RedisBroker does not.
            if len(args) > 0:
                assert len(args) < 2
                middleware = None if args[0] is None else args[0]
                args = []
            else:
                middleware = None

        if middleware is None:
            middleware = list(m() for m in default_middleware)
        else:
            middleware = list(middleware)

        if integration is not None:
            if SentryMiddleware not in (m.__class__ for m in middleware):
                middleware.insert(0, SentryMiddleware())

        kw["middleware"] = middleware
        original_broker__init__(self, *args, **kw)

    Broker.__init__ = sentry_patched_broker__init__


class DramatiqIntegration(OriginalDramatiqIntegration):
    @staticmethod
    def setup_once() -> None:
        _patch_dramatiq_broker()
