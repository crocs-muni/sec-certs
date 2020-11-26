import json
from datetime import date
from pathlib import Path

from sec_certs.dataset import CCDataset, FIPSDataset
from sec_certs.certificate import CommonCriteriaCert, FIPSCertificate, FIPSAlgorithm

serializable_complex_types = (
    CCDataset, FIPSDataset, CommonCriteriaCert, CommonCriteriaCert.MaintainanceReport,
    CommonCriteriaCert.ProtectionProfile,
    FIPSCertificate, FIPSAlgorithm)
serializable_complex_types_dict = {x.__name__: x for x in serializable_complex_types}


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, serializable_complex_types):
            return {**{'_type': type(obj).__name__}, **obj.to_dict()}
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, date):
            return str(obj)
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)


class CustomJSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if '_type' in obj and obj['_type'] in serializable_complex_types_dict.keys():
            complex_type = obj.pop('_type')
            return serializable_complex_types_dict[complex_type].from_dict(obj)

        return obj
