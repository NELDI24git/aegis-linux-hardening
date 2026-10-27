# Disposable integration matrix

`run-container-matrix.sh` builds disposable Ubuntu 24.04, Debian 12 and Fedora-family containers and executes the full pytest suite inside each image.

Containers cover package, provenance and parser compatibility. Use disposable Linux VMs for systemd, firewall persistence, SSH reload, boot/mount controls and kernel runtime behavior. Keep an out-of-band console available when testing remote-access or firewall remediation.

```bash
./integration/run-container-matrix.sh
# or
CONTAINER_ENGINE=podman ./integration/run-container-matrix.sh
```
