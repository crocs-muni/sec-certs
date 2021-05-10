FROM ubuntu

#installing dependencies
RUN apt-get update
RUN apt-get install python3 -y
RUN apt-get install python3-pip -y
RUN apt-get install python3-venv -y
RUN apt-get install git -y
#------installing the needed thing for PyPDF2 and pdftotext-------------------------------------
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install build-essential libpoppler-cpp-dev pkg-config python3-dev poppler-utils -y
RUN apt-get install libqpdf-dev -y
RUN apt-get install pkg-config -y
#-----------------------------------------------------------------------------------------------


RUN git clone https://github.com/crocs-muni/sec-certs.git /opt/sec-certs

#creating the venv in a way that works, the activation script doesn't work in Docker, we do manualy what it does
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install dependencies:
RUN cp /opt/sec-certs/requirements.txt .
RUN pip install wheel
RUN pip install -r requirements.txt
#just to be sure that pdftotext is in $PATH
ENV PATH /usr/bin/pdftotext:${PATH}


# Run the application:
CMD ["python3", "/opt/sec-certs/examples/cc_oop_demo.py"]
