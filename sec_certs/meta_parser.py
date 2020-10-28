class MetaParser:
    def parse_certs_from_html(self):
        raise NotImplementedError('Meant to be provided by child classes')

    def parse_certs_from_csv(self):
        raise NotImplementedError('Meant to be provided by child classes')


class CCMetaParser(MetaParser):
    def __init__(self):
        self.records = {}

    def parse_meta(self):
        self.parse_certs_from_csv()
        self.parse_certs_from_html()

        return self.records

    def parse_certs_from_csv(self):
        pass

    def parse_certs_from_html(self):
        pass


class FIPSMetaParser(MetaParser):
    def __init__(self):
        pass