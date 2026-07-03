# kube_exec.py

## Purpose

Exploits a Kubernetes service account token that has been granted the
"get" permission on the nodes/proxy resource, without corresponding
permission to list or get pods through the standard cluster API server.

The nodes/proxy permission allows a caller to reach a node's kubelet API
directly (default port 10250) and issue commands through it. If a
privileged pod is scheduled on that node with a hostPath volume mounting
the host's root filesystem ("/"), this effectively grants arbitrary
command execution on the underlying host, even though the token has no
broader Kubernetes RBAC permissions.

## What it does

The script automates two steps.

Discovery: it queries the kubelet's own /pods endpoint on a given node
directly, bypassing the cluster API server since that path is not
authorized for this token, and looks for a pod that is both privileged
and has a hostPath volume mounting "/".

Execution: once a suitable pod and container are found, it opens a
websocket connection to the kubelet's /exec endpoint for that pod and
streams the output of the requested command back to stdout.

## What is automatic versus what you supply

The service account token is read from the standard in-pod location at
/var/run/secrets/kubernetes.io/serviceaccount/token, and the cluster API
server address is read from the KUBERNETES_SERVICE_HOST and
KUBERNETES_SERVICE_PORT environment variables that Kubernetes injects
into every pod automatically. Neither of these needs to be supplied
manually.

The one value that cannot be discovered from inside the pod with this
token's permissions is the target node's IP address, since finding it
normally requires listing nodes or pods through the cluster API server.
That value must be supplied as the first command line argument, and it
is simply the IP address of the box or node currently being targeted.

## Requirements

Must be run from inside a pod that has an in-cluster service account
token with at least get on nodes/proxy. Requires the Python websockets
library to be importable in that pod's environment.

## Usage

```
python3 kube_exec.py <node_ip> <command> [args...]
```

node_ip is the IP address of the target Kubernetes node, the box's main
IP as seen from outside the cluster, for example the address used for
the original nmap scan.

command is the command to execute inside the privileged container,
followed by its arguments as separate words. If omitted, it defaults to
id as a quick sanity check.

## Examples

Confirm access and see what user or context you land in:

```
python3 kube_exec.py 10.129.244.214 id
```

Read a file from the underlying host filesystem, where the privileged
pod's hostPath mount exposes the host root at /host/root inside the
container:

```
python3 kube_exec.py 10.129.244.214 cat /host/root/root/root.txt
```

## Notes

Commands with arguments are split on whitespace and passed to the
kubelet exec API as separate parameters, matching how the kubelet
expects the command array. Arguments containing spaces are not
supported without further quoting logic, but this is not needed for
straightforward commands like cat against a known path.

TLS certificate verification is disabled when connecting to the kubelet
API, since kubelets typically present certificates that will not
validate against a standard CA trust store from this vantage point.
This is expected in this context and not a bug.
