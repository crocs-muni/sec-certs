FROM ubuntu:noble AS intermediate

ENV DEBIAN_FRONTEND="noninteractive" 
RUN apt-get update
RUN apt-get install -y git

# Filter the current dir for git-tracked files only.
WORKDIR /tmp
COPY . /tmp
RUN mkdir /output
RUN git ls-files | xargs cp -r --parents -t /output
COPY .git /output/.git

FROM ubuntu:noble

ENV DEBIAN_FRONTEND="noninteractive" 
ENV MONGO_VERSION 8.0
RUN apt-get update
RUN apt-get install -y gnupg curl openssl

# Add MongoDB GPG key and repository
RUN curl -fsSL https://www.mongodb.org/static/pgp/server-${MONGO_VERSION}.asc | \
    gpg -o /usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg --dearmor && \
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/${MONGO_VERSION} multiverse" | tee /etc/apt/sources.list.d/mongodb-org-${MONGO_VERSION}.list

# Install system dependencies
RUN apt-get update
RUN apt-get install -y python3 python3-pip python3-venv python3-dev git \
    tzdata build-essential libpoppler-cpp-dev pkg-config libqpdf-dev default-jdk \
    tesseract-ocr tesseract-ocr-eng tesseract-ocr-fra tesseract-ocr-deu \
    mongodb-org redis
RUN rm -rf /var/lib/apt/lists/*

# Add our user
ENV USER="user"
ENV NB_UID=1001
ENV NB_GID=1001
ENV HOME /home/${USER}

RUN groupadd -g ${NB_GID} -o ${USER}
RUN adduser --disabled-password \
  --gecos "Default user" \
  --uid ${NB_UID} \
  --gid ${NB_GID} \
  ${USER}

# Get the intermediate files from the previous stage
RUN mkdir ${HOME}/sec-certs-page
WORKDIR ${HOME}/sec-certs-page
COPY --chown=${NB_UID}:${NB_GID} --from=intermediate /output ${HOME}/sec-certs-page

# Mongodb
RUN mkdir -p /data/db && chown -R ${NB_UID}:${NB_GID} /data/db

# Flask instance dir
RUN mkdir -p ${HOME}/sec-certs-page/instance && chown -R ${NB_UID}:${NB_GID} ${HOME}/sec-certs-page/instance

# Make sure the permissions are right.
RUN chown -R ${NB_UID}:${NB_GID} ${HOME}
USER ${USER}

# Create virtual environment
ENV VENV_PATH=${HOME}/venv
RUN python3 -m venv ${VENV_PATH}
ENV PATH="${VENV_PATH}/bin:$PATH"

# Install some dependencies
RUN pip3 install -U setuptools wheel pip && \
    pip3 install notebook jupyterlab

# Install the page
RUN git checkout page
RUN pip3 install -e .
RUN python3 -m spacy download en_core_web_sm
RUN rm -rf ${HOME}/.cache

# Setup the config files
RUN cp config/example.config.py instance/config.py
RUN cp config/example.settings.yaml instance/settings.yaml
RUN sed -i "s/SERVER_NAME = \"localhost:5000\"//" instance/config.py
RUN sed -i "s/some proper randomness here/$(openssl rand -hex 32)/" instance/config.py
RUN sed -i "s/TURNSTILE_SITEKEY = \"\"/TURNSTILE_SITEKEY = \"1x00000000000000000000BB\"/" instance/config.py
RUN sed -i "s/TURNSTILE_SECRET = \"\"/TURNSTILE_SECRET = \"1x0000000000000000000000000000000AA\"/" instance/config.py

# Make the volumes
VOLUME /data/db
VOLUME ${HOME}/sec-certs-page/instance

EXPOSE 5000
CMD mongod --fork --logpath mongo.log && redis-server --daemonize yes --logfile redis.log && flask -A sec_certs_page run -h 0.0.0.0 -p 5000
