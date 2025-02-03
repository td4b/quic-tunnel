Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/jammy64"  # Ubuntu 22.04 LTS
  
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"  # Allocate 2GB RAM
    vb.cpus = 2         # Use 2 CPU cores
  end

  # Ensure the synced folder works correctly on Windows
  config.vm.synced_folder ".", "/vagrant", disabled: true  # Disable default sync
  config.vm.synced_folder "C:/Users/YourUsername/data", "/home/ubuntu", type: "virtualbox"

  # Optional: Provisioning inside the VM
  config.vm.provision "shell", inline: <<-SHELL
    echo "Hello from inside the VirtualBox VM!"
    ls -lah /home/ubuntu  # Verify sync works
  SHELL
end

