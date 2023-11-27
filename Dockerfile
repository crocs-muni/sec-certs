# First stage just copies the content of the git repo to /tmp so that we can copy it to the final image
# Note that if your folder with repository contains some large files, they should be added to .dockerignore
FROM ubuntu:jammy-20220428 AS intermediate

RUN apt-get update
RUN apt-get install git -y

WORKDIR /tmp
COPY . /tmp
RUN mkdir /output
RUN git ls-files | xargs cp -r --parents -t /output
COPY .git /output/.git

FROM ubuntu:jammy-20220428

ENV USER="user"
ENV NB_UID=1000
ENV NB_GID=1000
ENV HOME /home/${USER}

#installing dependencies
RUN apt-get update && apt-get upgrade -y
RUN apt-get install python3.10 -y
RUN apt-get install python3-venv -y
RUN apt-get install git -y
RUN apt-get install curl -y

# Install dependencies fo PyPDF2 and pdftotext
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install build-essential libpoppler-cpp-dev pkg-config python3-dev -y
RUN apt-get install libqpdf-dev -y
RUN apt-get install default-jdk -y
RUN apt-get install tesseract-ocr tesseract-ocr-eng tesseract-ocr-deu tesseract-ocr-fra -y


RUN groupadd -g ${NB_GID} -o ${USER}
RUN adduser --disabled-password \
  --gecos "Default user" \
  --uid ${NB_UID} \
  --gid ${NB_GID} \
  ${USER}

RUN chown -R ${NB_UID}:${NB_GID} ${HOME}
USER ${USER}

# Get the intermediate files from the previous stage
RUN mkdir ${HOME}/sec-certs
WORKDIR ${HOME}/sec-certs
COPY --chown=${NB_UID}:${NB_GID} --from=intermediate /output ${HOME}/sec-certs

# Create virtual environment
ENV VENV_PATH=${HOME}/venv
RUN python3 -m venv ${VENV_PATH}
ENV PATH="${VENV_PATH}/bin:$PATH"

# Install dependencies, notebook is because of mybinder.org
RUN \
  pip3 install -U pip wheel pip-tools && \
  pip-sync requirements/requirements.txt && \
  pip3 install --no-cache notebook jupyterlab && \
  pip3 install -e . && \
  python3 -m spacy download en_core_web_sm

# just to be sure that pdftotext is in $PATH
ENV PATH /usr/bin/pdftotext:${PATH}

# Run the application:
ENTRYPOINT ["sec-certs"]
