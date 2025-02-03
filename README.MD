
Vagrant on WLS.

```bash
vagrant plugin install vagrant-qemu
vagrant up --provider qemu-kvm
sudo dnf install qemu-kvm libvirt libguestfs-tools virt-install rsync
sudo systemctl enable --now libvirtd

export VAGRANT_DEFAULT_PROVIDER=docker
```

Generate CA.

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout ca.key -out ca.crt -days 3650 -nodes -subj "/CN=QUIC-CA" \
-addext "basicConstraints=critical,CA:TRUE" \
-addext "keyUsage=critical,keyCertSign,cRLSign"
```

Generate Server cert.

```bash
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout server.key -out server.csr -nodes -subj "/CN=quic-server" \
-addext "subjectAltName=DNS:quic-server,DNS:localhost,IP:127.0.0.1" \
-addext "keyUsage=critical,digitalSignature,keyEncipherment" \
-addext "extendedKeyUsage=serverAuth"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 \
-extfile <(printf "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:quic-server,DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
```

Generate Client Cert.

```bash
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout client.key -out client.csr -nodes -subj "/CN=quic-client" \
-addext "subjectAltName=DNS:quic-client" \
-addext "keyUsage=critical,digitalSignature,keyEncipherment" \
-addext "extendedKeyUsage=clientAuth"

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650 \
-extfile <(printf "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:quic-client\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth")
```