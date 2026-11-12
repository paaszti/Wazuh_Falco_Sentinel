# Wazuh + Falco + MS Sentinel Integration — Container Escape Detection Lab

A self-contained lab that wires **Falco** runtime security into a **Wazuh** SIEM
and forwards the correlated alerts to **Microsoft Sentinel**,
where multi-stage **KQL** analytics reconstruct container-escape attack chains. An
automated **SOC responder** closes the loop by quarantining the compromised pod and
killing attacker listeners.

The deliberately vulnerable target is **DVWA** (Damn Vulnerable Web Application),
running privileged in a MicroK8s cluster so that real container-escape techniques
can be executed and observed end to end.

> ⚠️ **This is a security research / lab project.** It intentionally deploys a
> vulnerable, privileged workload and ships working attack tooling. Run it only in
> an isolated environment you own. Never deploy any of it on a production or
> internet-exposed cluster.

---

## Table of contents

- [Architecture](#architecture)
- [Detection pipeline (data flow)](#detection-pipeline-data-flow)
- [Repository layout](#repository-layout)
- [Components](#components)
  - [Target: DVWA](#target-dvwa)
  - [Falco detection rules](#falco-detection-rules)
  - [Wazuh ingestion rules](#wazuh-ingestion-rules)
  - [Wazuh Kubernetes deployment](#wazuh-kubernetes-deployment)
  - [KQL correlation (Sentinel)](#kql-correlation-sentinel)
  - [SOC responder](#soc-responder)
  - [Attack files](#attack-files)
- [Attack-chain model](#attack-chain-model)
- [Deployment](#deployment)
- [Tuning notes](#tuning-notes)
- [TODO](#todo)

---

## Architecture

```
                       ┌──────────────────────────────────────────────┐
                       │  MicroK8s node                               │
                       │                                              │
  attacker ──HTTP──▶   │   ┌───────────────┐    syscalls    ┌───────┐ │
  (cmd injection)      │   │ dvwa pod      │ ─────────────▶ │ Falco │ │
                       │   │ (privileged,  │   (modern eBPF) │ (DS)  │ │
                       │   │  hostPID)     │                └───┬───┘ │
                       │   └───────────────┘                    │     │
                       │                              /var/log/falco/ │
                       │                                falco.json    │
                       │                                    │         │
                       │                            ┌───────▼───────┐ │
                       │                            │ Wazuh agent   │ │
                       │                            │ (on node)     │ │
                       │                            └───────┬───────┘ │
                       └────────────────────────────────────┼─────────┘
                                                             │ 1514/tcp
                                               ┌─────────────▼─────────────┐
                                               │ Wazuh manager (master +   │
                                               │ worker, cluster) on k8s   │
                                               │  • decode falco JSON      │
                                               │  • FIM (cron persistence) │
                                               │  • custom rules 100600+   │
                                               └─────────────┬─────────────┘
                       alerts.json (tail sidecar in│
                           wazuh-manager-worker pod)│
                                               ┌─────────────▼─────────────┐
                                               │ alerts-forwarder sidecar  │
                                               │ → stdout → ContainerLogV2 │
                                               └─────────────┬─────────────┘
                                                             │ Container Insights
                                               ┌─────────────▼─────────────┐
                                               │ Azure Log Analytics /      │
                                               │ Microsoft Sentinel         │
                                               │  • Wazuh_Falco_Alerts (fn) │
                                               │  • correlation rules        │
                                               │  • playbooks → MS Teams     │
                                               └─────────────┬─────────────┘
                                                             │ incident (queue msg)
                                               ┌─────────────▼─────────────┐
                                               │ soc-responder.sh (on node)│
                                               │  • label pod quarantine   │
                                               │  • NetworkPolicy isolates │
                                               │  • kill listener PIDs      │
                                               └───────────────────────────┘
```

---

## Detection pipeline (data flow)

1. **Falco** runs as a DaemonSet using the `modern_ebpf` driver and the
   Kubernetes metadata collector (`k8smeta`). Custom rules (`custom-rules.yaml`)
   detect attack behaviour in the monitored `dvwa` namespace and write JSON events
   to `/var/log/falco/falco.json` on the host, each enriched with a
   `wazuh_integration: falco` field.
2. A **Wazuh agent** on the node reads `falco.json` and forwards events to the
   Wazuh manager.
3. The **Wazuh manager** decodes the JSON and classifies each Falco event by
   priority using custom rules `100600–100607` (`falco-rules.xml`). File Integrity
   Monitoring (FIM / syscheck) independently flags writes to cron paths
   (persistence).
4. An **`alerts-forwarder` sidecar** — a container running *inside the
   `wazuh-manager-worker` pod* — tails `alerts.json` to stdout so Azure
   Container Insights ships it into `ContainerLogV2`.
5. In **Sentinel**, the `Wazuh_Falco_Alerts` function parses and normalises those
   logs into a typed schema and labels each event with a kill-chain **Stage**.
   Scheduled analytics rules correlate ordered stage sequences into single escape
   incidents.
6. Each incident triggers a **Sentinel playbook** that notifies the SOC in
   **Microsoft Teams** and hands the operator a per-attack checklist to confirm the
   alert is a true positive.
7. An incident enqueues a message that the **SOC responder** on the node consumes:
   it validates the payload, labels the pod `quarantine=true` (which the
   `quarantine` NetworkPolicy isolates), and kills the offending listener PIDs.

---

## Repository layout

```
.
├── dvwa.yaml                 # DVWA namespace, privileged Deployment, LoadBalancer Service
├── Dockerfile                # DVWA image variant (blanks the root password)
├── falco-values.yaml         # Helm values for Falco (driver, outputs, custom rules)
├── custom-rules.yaml         # Falco detection rules (source of truth; also inlined in values)
├── falco-rules.xml           # Wazuh rules that ingest/classify Falco JSON (IDs 100600–100607)
├── quarantine-np.yaml        # NetworkPolicy that isolates quarantined pods
├── soc-responder.sh          # Node-side automated responder (quarantine + kill)
├── kql/
│   ├── Wazuh_Falco_Alerts.kql            # Parser/normaliser + Stage labelling (Sentinel function)
│   ├── rule1_escape_hostfs_mount.kql     # hostfs mount + chroot escape chain      ┐ being merged
│   ├── rule2_escape_persistence_listener.kql  # escape → persistence / listener    ┘ into one rule
│   ├── rule3_escape_kernel_module.kql    # malicious kernel-module load escape
│   └── rule5_escape_process_injection.kql     # ptrace process-injection escape
├── attack-files/
│   ├── rev-shell.c           # LKM reverse-shell kernel module
│   ├── Makefile              # Builds the kernel module
│   ├── infect.c              # ptrace shellcode injector
│   └── process-injection.py  # Benign victim process for the injection demo
└── wazuh/                    # Vendored wazuh-kubernetes manifests (Kustomize)
    └── envs/lab/             # Lab overlay: images, resources, rules mount, sidecar, Azure filter
```

The `wazuh/` subtree is a vendored copy of the upstream
[wazuh-kubernetes](https://github.com/wazuh/wazuh-kubernetes) deployment. All
integration-specific changes live in the `wazuh/envs/lab/` overlay; the rest of the
files at the repository root are the integration itself.

---

## Components

### Target: DVWA

`dvwa.yaml` deploys DVWA into a `dvwa` namespace with a configuration chosen to make
container-escape techniques possible:

- `securityContext.privileged: true` — full capabilities, access to host devices.
- `hostPID: true` — the pod shares the host PID namespace (enables host-process
  visibility and injection scenarios).
- Exposed via a `LoadBalancer` Service on port 80.

`Dockerfile` builds from `vulnerables/web-dvwa` and runs `usermod -p '' root`,
blanking the root password so in-container privilege escalation (e.g. `su`) is
trivial — a deliberate lab convenience, imported into MicroK8s and referenced as
`dvwa:test` with `imagePullPolicy: Never`.

### Falco detection rules

The authoritative, most up-to-date ruleset is the `customRules` block in
**`falco-values.yaml`** — that is what Falco actually loads via Helm, and the
descriptions below are taken from it. `custom-rules.yaml` is a standalone, more
readable copy of the same rules; treat it as reference and keep it in sync with the
Helm values when editing.

Everything is
scoped to the monitored namespace via the `monitored_ns` list (`dvwa`) and the
`lab_in_scope` macro (in a container **and** in a monitored namespace), so the
noise from cluster system workloads is excluded. Allow-lists (`lab_*_allowed_ports`,
`lab_node_ips`, `lab_web_processes`, …) encode what is normal for this lab so only
anomalies fire.

| Rule | Priority | MITRE | What it catches |
|------|----------|-------|-----------------|
| Execution: Interactive Shell in Container | NOTICE | T1059.004 | Shell binary with an attached TTY |
| Discovery: Mount Table and Partition Read | NOTICE | T1083/T1082 | Reads of `/proc/mounts`, mountinfo, `/proc/partitions` |
| Discovery: Process Enumeration via /proc | NOTICE | T1057 | Opening `/proc` directory |
| Discovery: IP Address Lookup via hostname | NOTICE | T1016 | `hostname -i/-I` |
| Discovery: Kernel Information via uname | NOTICE | T1082 | `uname` (incl. busybox applet), any flags |
| Discovery: Kernel Version File Read | NOTICE | T1082 | `/proc/version`, `osrelease`, etc. (excludes procps noise) |
| Discovery: Network Configuration Read | NOTICE | T1016 | `/proc/net/{route,arp,fib_trie,dev}`, `/etc/hosts` |
| Discovery: Kernel Module List Read | WARNING | T1082 | `/proc/modules` (`lsmod`) |
| Privilege Escalation: su to root | WARNING | T1078.003 | `su`, `su -`, `su root` |
| Privilege Escalation: Mount in Container | CRITICAL | T1611 | `mount` syscall (escape precursor) |
| Privilege Escalation: chroot in Container | CRITICAL | T1611 | `chroot` syscall |
| Privilege Escalation: Kernel Module Load/Unload | CRITICAL | T1547.006 | `init_module`/`finit_module`/`delete_module` |
| Defense Evasion: ptrace Attach | CRITICAL | T1055.008 | `PTRACE_ATTACH`/`PTRACE_SEIZE` (injection) |
| Defense Evasion: Executable Permission Set | WARNING | T1222.002 | `chmod +x` (mode contains `S_IX`) |
| Command and Control: Ingress Transfer from Web Process | CRITICAL | T1105/T1571 | Web process connects out to a non-standard port |
| Command and Control: Listener on Non-Standard Port | WARNING | T1571 | `listen()` outside the allow-list |
| Command and Control: Container→Node Connection | WARNING | T1571 | Connect to a node IP on a non-standard port |
| Command and Control: Host Listener on Non-Standard Port | NOTICE | T1571 | Node-level (non-container) listener outside allow-list |

Rules record both **attempts and successes** for key syscalls (`mount`, `chroot`,
kernel module, `ptrace`) via `res=` in the output, so the correlation layer can
distinguish a failed escape from a successful one.

### Wazuh ingestion rules

`falco-rules.xml` defines Wazuh rules `100600–100607`:

- **100600** — base rule: decodes events where `output_fields.wazuh_integration ==
  falco` as JSON.
- **100601–100607** — children that map Falco `priority`
  (Info → Emergency) onto Wazuh severity levels 4, 6, 8, 10, 12, 14, 16.

This preserves Falco's severity through to Wazuh alerting and, downstream, to the
Sentinel `WazuhLevel` field.

### Wazuh Kubernetes deployment

Deployed with Kustomize from `wazuh/envs/lab/` (which layers on `../local-env`):

- **`kustomization.yml`** — pins Wazuh images to `4.14.9`, generates the
  `wazuh-custom-rules` ConfigMap from `falco-rules.xml`, and applies the lab
  patches.
- **`rules-mount.yaml`** — mounts the Falco ingestion rules into both the master
  and worker managers at `/wazuh-config-mount/etc/rules/falco-rules.xml`.
- **`worker-sidecar.yaml`** — adds the `alerts-forwarder` busybox sidecar
  **to the `wazuh-manager-worker` StatefulSet** (it runs as a second container in
  the worker pod, with `alerts.json` mounted read-only), `tail -F`ing the alerts to
  stdout for Container Insights pickup.
- **`resources.yaml`** — CPU/memory requests and limits for the managers.
- **`azure-log-filter.yaml`** — pod-template annotations so Container Insights only
  ships the `alerts-forwarder` stream (`fluentbit.io/exclude*`) and not the noisy
  manager/indexer/dashboard logs.

### KQL correlation (Sentinel)

**`Wazuh_Falco_Alerts.kql`** is the foundation — intended to be saved as a Sentinel
**function**. It:

- filters `ContainerLogV2` to the `alerts-forwarder` sidecar;
- parses the Wazuh JSON, normalising the timestamp to ISO-8601 and unifying the
  `Host` key across Falco alerts (`data.hostname`) and FIM alerts (agent name);
- projects a flat, typed schema (pod, container, proc, cmdline, mount/chroot/ptrace
  args, remote IP/port, FIM path, …);
- derives `Outcome` (ok / failed) from the `res=` field; and
- assigns each event a kill-chain **`Stage`** label (see below).

The scheduled analytics rules each look for a specific escape pattern over a time
window and emit one incident per host when the ordered stage sequence is present.
They use `summarize ... by Host` with `minif`/`maxif` to establish ordering, then
gate on **sequence** (e.g. `T_Shell <= T_HostFS`) so that isolated low-severity
events don't raise an incident — only a coherent chain does.

Two correlation queries are documented here:

| Rule | Detects | Core condition |
|------|---------|----------------|
| `rule3_escape_kernel_module` | Malicious kernel-module load escape | presence of `3-KernelModule`, correlated with recon (`0-KernelRecon`/`0-NetRecon`, `0-ModuleListRead`) and priv-esc (`2-PrivEsc`/`2-ExecPerm`) context |
| `rule5_escape_process_injection` | ptrace process-injection escape | presence of `3-ProcessInjection`, correlated with `0-ProcEnum`, recon completeness, priv-esc and any follow-on node connection |

Each returns a per-host summary (first/last seen, the set of observed stages, chain
length, pod/container IDs, the relevant PIDs and the command lines) so an incident
carries the full chain, not a single event.


#### Sentinel playbooks & notification

On the Sentinel side, every attack scenario has a dedicated **playbook** (Logic App)
attached to its analytics rule. When an incident is raised:

- a **notification is posted to Microsoft Teams**, alerting the SOC that a container
  escape has been detected; and
- the playbook provides the **SOC operator with scenario-specific triage guidance** —
  the concrete checks to run to confirm the alert is a true positive and rule out a
  false positive before the automated response is trusted or escalated.

This keeps a human in the loop: the KQL correlation already filters to coherent
chains, and the playbook gives the operator a per-attack checklist to validate the
incident.

### SOC responder

`soc-responder.sh` runs on the node and polls an Azure Storage queue (configured via
`QUEUE_URL` and `SAS` environment variables) for incident messages produced by
Sentinel automation. For each message it:

1. **Parses** the JSON payload (`pod`, `node`, `port`, `incident`).
2. **Targets check** — skips the message unless `node` matches one of this host's
   own IPs (so each node only acts on its own incidents).
3. **Validates** (defence against spoofed/invalid input): pod name must match
   `dvwa-[a-z0-9-]+`, port must be 4–5 digits, and a blocklist of
   infrastructure ports is rejected so the responder can't be tricked into killing
   cluster services.
4. **Responds**: labels the pod `quarantine=true` (picked up by the NetworkPolicy),
   then finds the PIDs listening on the reported port via `ss` and kills them
   (`TERM`, then `KILL` after a grace period), skipping PID ≤ 1.
5. **Deletes** the queue message.

Supports a `DRY=1` dry-run mode that prints intended actions instead of executing
them. The pod-delete step is present but commented out — quarantine + kill is the
default, less destructive response.

`quarantine-np.yaml` is the enforcement mechanism: a NetworkPolicy in the `dvwa`
namespace selecting `quarantine: "true"` pods with empty Ingress/Egress rules,
cutting all pod network traffic once the responder labels it.

### Attack files

`attack-files/` contains the tooling used to exercise the detections (for lab use
only):

- **`rev-shell.c` + `Makefile`** — a Loadable Kernel Module that uses
  `call_usermodehelper` to spawn a reverse shell from kernel space. Loading it
  triggers the kernel-module escape chain (`rule3`). Edit `<container_ip>` before
  building.
- **`infect.c`** — a classic `ptrace` shellcode injector (`PTRACE_ATTACH` →
  `POKETEXT` → `SETREGS`) that injects an execve(`/bin/sh`) payload into a running
  process. Triggers the process-injection chain (`rule5`).
- **`process-injection.py`** — a trivial idle victim process to inject into.

---

## Attack-chain model

The Sentinel layer reasons about numbered **stages** rather than individual alerts,
which is what lets isolated events be ignored and real chains be caught. The `Stage`
values assigned by `Wazuh_Falco_Alerts.kql`:

| Stage | Meaning |
|-------|---------|
| `0-KernelRecon` | uname / kernel-version file reads |
| `0-NetRecon` | hostname `-i`, network-config reads |
| `0-ProcEnum` | `/proc` enumeration |
| `0-MountTableRead` | mount table / partitions read |
| `0-ModuleListRead` | `/proc/modules` read |
| `0-ToolTransfer` | ingress tool download from web process |
| `1-Shell` | interactive shell in container |
| `2-PrivEsc` | `su` to root |
| `2-ExecPerm` | `chmod +x` |
| `3-HostFS` / `3-HostFSAttempt` | host filesystem mount (success / attempt) |
| `3-MountOther` | non-device mount |
| `3-Chroot` | chroot |
| `3-KernelModule` / `…Attempt` | kernel-module load (success / attempt) |
| `3-ProcessInjection` / `…Attempt` | ptrace injection (success / attempt) |
| `4-Persistence` | cron file write (from Wazuh FIM) |
| `5-Listener` | listener on non-standard port |
| `5-NodeConnection` / `…Failed` | container→node connection |
| `6-HostListener` | listener on the node itself |

A typical **hostfs-mount escape** chain (detected by `rule1`) therefore reads as:
`0-KernelRecon` + `0-NetRecon` → `1-Shell` → `0-MountTableRead` → `3-HostFS` →
`3-Chroot`, with `rule2` firing if it is followed by a `4-Persistence` or
`5-Listener` stage.

---

## Deployment

> Prerequisites: a MicroK8s cluster (the manifests assume `microk8s kubectl` and the
> local image registry), Helm 3, and — for the Sentinel/responder half — an Azure
> Log Analytics workspace with Container Insights and a Storage queue.

**1. Build and import the DVWA image**

```bash
docker build -t dvwa:test .
# import into MicroK8s (dvwa.yaml uses imagePullPolicy: Never)
docker save dvwa:test > dvwa.tar && microk8s ctr image import dvwa.tar
```

**2. Deploy the target**

```bash
microk8s kubectl apply -f dvwa.yaml
microk8s kubectl apply -f quarantine-np.yaml
```

**3. Deploy Falco** (loads the custom rules from the Helm values)

```bash
helm install falco falcosecurity/falco -n falco --create-namespace -f falco-values.yaml
```

**4. Generate the Wazuh indexer/dashboard certificates.** Before deploying the
stack you must create the TLS certificates the indexer cluster and dashboard use.
Follow the official Wazuh Kubernetes deployment guide — the certificate-generation
step:

<https://documentation.wazuh.com/current/deployment-options/deploying-with-kubernetes/kubernetes-deployment.html>

The generated certs live under `wazuh/wazuh/certs/` (and are git-ignored by
`.gitignore`).

**5. Deploy Wazuh** (applies the lab overlay, including the Falco ingestion rules
and the alerts-forwarder sidecar)

```bash
microk8s kubectl apply -k wazuh/envs/lab
```

Update `lab_node_ips` in the Falco rules to your node addresses before deploying.

**6. Sentinel analytics** — save `kql/Wazuh_Falco_Alerts.kql` as a function named
`Wazuh_Falco_Alerts`, then create scheduled analytics rules from the correlation
queries (`rule3`, `rule5`, and the combined hostfs/persistence rule).

**7. SOC responder** — on the node, export `QUEUE_URL` and `SAS` for your Azure
Storage queue and run `./soc-responder.sh` (use `DRY=1 ./soc-responder.sh` first to
verify without taking action).

---

## Tuning notes

- **Scope** is controlled by the `monitored_ns` list — add namespaces there to widen
  coverage.
- **Allow-lists** (`lab_*_allowed_ports`, `lab_node_ips`, `lab_web_processes`,
  `lab_procps_tools`) are what keep the rules quiet. Review them when adapting the
  lab to a different cluster — stale node IPs or ports are the most common cause of
  missed or noisy detections.
- **Responder safety**: the port blocklist and pod-name regex in `soc-responder.sh`
  exist specifically to prevent a forged queue message from killing infrastructure —
  keep them aligned with `lab_host_listen_allowed_ports`.

---

## TODO

- [ ] **Provision all Microsoft Azure resources with Terraform** — Log Analytics
  workspace, Sentinel, the `Wazuh_Falco_Alerts` function and analytics rules, the
  Storage queue, the playbooks (Logic Apps) and the Teams connection — so the whole
  cloud side is reproducible as infrastructure-as-code instead of clicked together.
- [ ] De-duplicate the Falco ruleset so `custom-rules.yaml` and the `customRules`
  block in `falco-values.yaml` have a single source of truth.
