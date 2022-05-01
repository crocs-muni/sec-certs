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

# Download only snapshot of repository
RUN \
  curl -L https://api.github.com/repos/crocs-muni/sec-certs/tarball/main > sec-certs.tar.gz && \
  mkdir sec-certs && \
  tar zxf sec-certs.tar.gz --strip-components=1 --directory sec-certs && \
  rm sec-certs.tar.gz

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

# #just to be sure that pdftotext is in $PATH
ENV PATH /usr/bin/pdftotext:${PATH}

# # Run the application:
# CMD ["python3", "./cc_cli.py"]
