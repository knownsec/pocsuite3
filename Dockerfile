FROM ubuntu:bionic
MAINTAINER Knownsec 404 Team

env DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y \
        python3 \
        python3-pip \
        tmux \
        vim \
        wget \
        curl \
        zsh \
    && pip3 install --upgrade pip \
    && python3 -m pip install --upgrade pocsuite3 \
    && apt-get install -y sudo \
    && useradd -m pocsuite3 \
    && passwd --delete --unlock pocsuite3 \
    && echo "pocsuite3 ALL=(ALL:ALL) NOPASSWD: ALL" > /etc/sudoers.d/pocsuite3

USER pocsuite3

RUN sh -c "$(wget -O- https://raw.githubusercontent.com/13ph03nix/zsh-in-docker/master/zsh-in-docker.sh)" -- \
    -t https://github.com/spaceship-prompt/spaceship-prompt \
    -p git \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    && sudo apt-get autoremove -y \
    && sudo apt-get clean -y \
    && sudo rm -rf /var/lib/apt/lists/*

WORKDIR /home/pocsuite3
CMD ["zsh"]
