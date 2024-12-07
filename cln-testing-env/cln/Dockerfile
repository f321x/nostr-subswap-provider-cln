FROM elementsproject/lightningd:latest

RUN apt update && apt install -y cmake make automake libtool gcc git neovim python3-venv python3-pip

WORKDIR /root/plugins

COPY requirements.txt .

RUN pip install --force-reinstall -r requirements.txt

ENTRYPOINT ["lightningd"]