FROM seccerts/sec-certs

WORKDIR ${HOME}
RUN git clone https://github.com/crocs-muni/sec-certs sec-certs-page

WORKDIR ${HOME}/sec-certs-page
EXPOSE 5000

RUN git checkout page
RUN pip3 install -e .

RUN mkdir src/instance

RUN cp config/example.config.py src/instance/config.py
RUN cp config/example.settings.yaml src/instance/settings.yaml

CMD flask -A sec_certs_page run -h 0.0.0.0
