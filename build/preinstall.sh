sudo apt -y update
sudo apt -y upgrade

sudo apt -y install make
sudo apt -y install golang-1.10-go
sudo ln -s /usr/lib/go-1.10/bin/go /usr/bin/go

sudo rm -rf /home/ubuntu/go-cypherium
sudo rm -rf /home/ubuntu/genesis.json
sudo rm -rf /home/ubuntu/group.toml

mkdir /home/ubuntu/go-cypherium
