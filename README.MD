# quic-tunnel

<img src="https://github.com/td4b/quic-tunnel/blob/main/logo/quic-tunnel.png" alt="QUIC-Tunnel Logo" width="50%">

A simple go program that creates a networking tunnel used to route traffic between the client and the server.

# Routing

You may have to add NAT rules or remove some default routes if working inside a bridged VM environment. Since the server side of the tunnel is used as the gateway.

Additional ip tables, DNAT and SNAT configuration rules can be added to the client.go or server.go configuration settings to support your routing needs.

# Debug mode.

You can enable debug mode to view the TCP payloads received in the tunnel. Alternativley you can take a packet capture from one of the tunnel interfaces the program generates.

By default the debug logging is disabled to reduce round trip time and latency as the call is blocking.

# Generating mTLs Certificates

How to generate the MTLs Certificates used for authentication.

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