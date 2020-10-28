from abc import ABC, abstractmethod
from .dataset import Dataset
import pandas as pd


class CertLoader(ABC):
    def __init__(self, download_pdfs, meta_dir, pdf_dir):
        self.df = pd.DataFrame()
        self.download_pdfs = download_pdfs
        self.meta_dir = meta_dir
        self.pdf_dir = pdf_dir
        self.certs = {}

    @abstractmethod
    def load(self):
        pass


class CCCertLoader(CertLoader):

    def load_csv(self):
        pass

    def load_html(self):
        pass

    def load(self):
        self.load_csv()
        self.load_html()
        return self.certs


class FIPSCertLoader(CertLoader):
    def load_csv(self):
        pass

    def load_html(self):
        pass

    def load(self):
        self.load_csv()
        self.load_html()
        return self.certs

