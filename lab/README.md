# Live virtual machine lab

This path provisions four real Ubuntu 22.04 KVM guests. All four are running
on this host, and real packet capture, lossy communication and firewall
enforcement have passed acceptance checks. See ../docs/RESULTS.md. The setup
instructions below are for recreating the lab on a fresh host.

## Fedora host setup

From `/home/sirnike/MIT/InfoSecProject`, review and run:

```bash
cat lab/install-host-fedora.sh
sudo bash lab/install-host-fedora.sh
./lab/init.sh
```

Enter your password only in your terminal. The setup installs QEMU/KVM, libvirt,
Vagrant and its libvirt provider, then starts the appropriate virtualization
sockets. It does not edit sudoers, disable SELinux, alter host firewall policy,
or give the web service root permissions. The current user is already in the
libvirt group. Other users may need the standard libvirt group membership and a
new login. Keep any normal polkit authentication prompt local.

The Vagrant setup uses `qemu://system`, explicitly, because the isolated bridge
requires network management. It allocates 1 GiB RAM and one vCPU per VM. The base
box requires a download. The pure Python Scapy package is copied from the local
virtual environment, so guest provisioning and experiments need no public DNS
or internet access. The box already supplies Python, nftables and iproute2. First boot can take several minutes.
The default guest management NIC provides provisioning access; the experiment
NIC is on an isolated libvirt network with no forwarding. Do not attach the
experiment network to a public bridge.

Sources: [Fedora Vagrant documentation](https://developer.fedoraproject.org/tools/vagrant/vagrant-libvirt.html),
[libvirt daemon modes](https://libvirt.org/daemons.html),
[vagrant-libvirt installation](https://vagrant-libvirt.github.io/vagrant-libvirt/installation.html).

## Start and verify

`./lab/init.sh` creates a private random agent token and starts the guests. The
host dashboard reads that same local token; it never displays it. Agent control
ports are forwarded onto host loopback where Vagrant forwarding is available. On this host, the
controller discovers our named guests with virsh and uses their private
management addresses directly, on agent port 9100. All calls require the same
private token. The configured forwarding ports are:

| Peer | Experiment address | Host control port |
| --- | --- | --- |
| Atlas | 192.168.56.11 | 9101 |
| Birch | 192.168.56.12 | 9102 |
| Cedar | 192.168.56.13 | 9103 |
| Delta | 192.168.56.14 | 9104 |

Start the dashboard with `./start.sh`. Click **Check VM connections**, then
**Live VMs**. The UI must show four connected agents. Test benign traffic first,
then a bounded DoS or scan scenario. Use observation mode before enabling rules.
The root agent runs only inside each disposable guest and only accepts these
four destination addresses. Requests have a bearer token, fixed scenario choices,
30-second and 500-operations-per-second caps. No arbitrary shell commands can be
submitted through the app.

## Meaning of the scenarios

- Benign: repeated requests to the guest web service, at most eight per second.
- DoS: bounded UDP traffic to a guest UDP receiver. One sender is DoS, not DDoS.
- PortScan: bounded connection probes across 32 lab ports.
- BruteForce: repeated requests to an intentionally failing toy auth endpoint.
  This tests the pipeline and is not a full SSH/FTP brute-force implementation.

The dataset benchmark contains more classes than the live generators. The lab
cannot validate all CICIDS2017 categories merely because the benchmark model
has those classes.

## Loss, observation and enforcement

NetEm is applied only to the source experiment NIC's egress direction. Random
loss uses a Bernoulli model. Burst loss uses Gilbert–Elliott with mean bad-state
length four packets; parameters derive from the configured stationary drop rate.
ACKs and response traffic in the reverse direction are not deliberately dropped.
Use the destination sensor to observe traffic after link loss. Capture timestamps
come from the destination guest, so first-packet-to-decision wall time should
not be compared to the host clock without synchronization.

A prefix model classifies after 10 observed packets, or a shorter flow at close
or capture end. The host polls the authenticated sensor every 250 ms; this is a
small-scale research implementation, not a line-rate IPS. Source addresses are
metadata and never model inputs. A high attack score can install two nftables
rules for the exact bidirectional tuple at the destination, confirmed by the
agent before the UI says it blocked anything. Explanation work runs afterward.

AF_PACKET capture occurs before the guest input firewall, so captured packets
can include packets subsequently dropped by nftables. Destination application
counters and firewall counters are separately recorded. Do not describe raw
capture counts as delivered application traffic. The current application does
not calculate a universal malicious-bytes-before-block measure for every
protocol. HTTP request and UDP payload counters are the supported delivery
measurements.

Cleanup removes the experiment qdisc and the dedicated `inet flowlab` table,
not the guest's other firewall rules. The host sends stop/reset in a finally
block. The agent also resets after 60 seconds without an authenticated contact,
so a controller crash does not leave the experiment's rules indefinitely.

## Train models on real lab captures

The lab_completed and lab_prefix10 model sets are trained on 24 controlled
real capture sessions. Fixture model sets remain separate. This validates the
small lab, not general Internet attack detection. To extend it, collect labelled
episodes, prepare them using `flowlab prepare-pcaps`, and train another
packet-compatible model set. See the main README and `manifest.example.json`.

## Stop and remove

```bash
cd lab
vagrant halt
```

`vagrant destroy` removes the lab guests when you explicitly choose to discard
them. It is not part of automatic app cleanup. To inspect a guest:

```bash
vagrant ssh flowlab1
sudo journalctl -u flowlab-agent --no-pager -n 50
sudo nft list table inet flowlab
```

If VM startup fails, keep the exact error. Do not disable SELinux or flush host
firewall rules to work around a provisioning failure.

The source qdisc counters record measured link loss. On this guest image, tc
does not support RNG seeding; the UI records the fallback explicitly. Offline
packet corruption remains deterministic. The source PCAP is an egress capture,
not a guarantee of observation before NetEm; use qdisc counters for live loss.
