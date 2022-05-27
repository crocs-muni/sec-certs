FROM ubuntu:jammy-20220428

ENV USER="user"
ENV NB_UID=1000
ENV HOME /home/${USER}

#installing dependencies
RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN apt-get install python3-venv -y
RUN apt-get install git -y
RUN apt-get install curl -y

# Install dependencies fo PyPDF2 and pdftotext
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install build-essential libpoppler-cpp-dev pkg-config python3-dev -y
RUN apt-get install libqpdf-dev -y
RUN apt-get install default-jdk -y
RUN apt-get install graphviz -y

RUN adduser --disabled-password \
  --gecos "Default user" \
  --uid ${NB_UID} \
  ${USER}

RUN chown -R ${NB_UID} ${HOME}
USER ${USER}
WORKDIR ${HOME}

# Due to setuptools_scm for versioning, we need whole repository with .git
RUN git clone https://github.com/crocs-muni/sec-certs

WORKDIR ${HOME}/sec-certs

# Create virtual environment
ENV VENV_PATH=${HOME}/venv
RUN python3 -m venv ${VENV_PATH}
ENV PATH="${VENV_PATH}/bin:$PATH"

# Install dependencies, notebook is because of mybinder.org
RUN \
  pip3 install -U pip && \
  pip3 install wheel && \
  pip3 install -r requirements/requirements.txt && \
  pip3 install --no-cache notebook jupyterlab && \
  pip3 install -e .

# Download spacy language model
RUN python3 -m spacy download en_core_web_sm

# #just to be sure that pdftotext is in $PATH
ENV PATH /usr/bin/pdftotext:${PATH}

# # Run the application:
# CMD ["python3", "./cc_cli.py"]
