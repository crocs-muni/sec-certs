import requests


class RemoteTestResponse:
    def __init__(self, response: requests.Response):
        self.response = response

    def __getattr__(self, item):
        if hasattr(self.response, item):
            return getattr(self.response, item)

    @property
    def data(self):
        return self.response.content

    @property
    def json(self):
        return self.response.json()

    @property
    def is_json(self):
        mt = self.mimetype
        return mt is not None and (mt == "application/json" or mt.startswith("application/") and mt.endswith("+json"))

    @property
    def mimetype(self):
        ct = self.response.headers.get("content-type")

        if ct:
            return ct.split(";")[0].strip()
        else:
            return None

    @property
    def location(self):
        return self.response.headers.get("Location")

    @property
    def history(self):
        return [RemoteTestResponse(resp) for resp in self.response.history]


class RemoteTestClient:
    def __init__(self, base):
        self.base = base

    def get(self, *args, **kwargs) -> RemoteTestResponse:
        arg = list(args)
        url = arg.pop(0)
        if "follow_redirects" in kwargs:
            kwargs["allow_redirects"] = kwargs.pop("follow_redirects")
        else:
            kwargs["allow_redirects"] = False
        return RemoteTestResponse(requests.get(self.base + url, *arg, **kwargs))
