FROM elementsproject/lightningd:latest

RUN apt update && apt install -y cmake make automake libtool gcc git neovim

WORKDIR /root/plugins

COPY requirements.txt .

RUN pip install -r requirements.txt

ENTRYPOINT ["lightningd"]