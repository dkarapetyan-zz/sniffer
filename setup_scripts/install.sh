#!/usr/bin/env bash
sudo apt-get install python-pip gnuplot-x11 python-scapy python-pcapy python-pyx tcpdump tmux git zsh python-dev python-pandas ipython python-ipdb htop postgresql
sudo chsh -s /bin/zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
