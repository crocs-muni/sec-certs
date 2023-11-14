"""
This package exposes model (mostly transformers and classifiers) that apply complex transformations. These are to be
leveraged by members of Dataset package and are directly applied on members of Sample class (or on built-in objects).
"""

from sec_certs.model.cc_matching import CCSchemeMatcher
from sec_certs.model.cpe_matching import CPEClassifier
from sec_certs.model.fips_matching import FIPSProcessMatcher
from sec_certs.model.reference_finder import ReferenceFinder
from sec_certs.model.sar_transformer import SARTransformer
from sec_certs.model.transitive_vulnerability_finder import TransitiveVulnerabilityFinder

__all__ = [
    "CPEClassifier",
    "CCSchemeMatcher",
    "FIPSProcessMatcher",
    "ReferenceFinder",
    "TransitiveVulnerabilityFinder",
    "SARTransformer",
    "ReferenceAnnotator",
    "ReferenceAnnotatorTrainer",
    "ReferenceSegmentExtractor",
]
