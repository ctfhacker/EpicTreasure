# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # config.vm.box = "ubuntu/xenial64"
  config.vm.box = "ubuntu/xenial64"

  # config.vm.box = "xenial64"
  # config.vm.box_url = "https://cloud-images.ubuntu.com/xenial/current/xenial-server-cloudimg-amd64-vagrant.box"

  config.vm.provision :shell, :path => "et_setup.sh", :privileged => false
  # config.ssh.username = 'vagrant'
  # config.ssh.forward_agent = true

  config.vm.synced_folder "host-share", "/home/ubuntu/vmshare"

  # config.vm.network "forwarded_port", guest: 80, host: 8899
  config.vm.network "private_network", type: "dhcp"

  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--memory", "8192"]
    vb.customize ["modifyvm", :id, "--cpus", "4"]
  end

end
