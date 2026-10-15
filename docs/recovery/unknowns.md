# Unknowns / Open Questions

| ID | Question | Current hypothesis / next step |
|----|----------|-------------------------------|
| U-1 | Actual upstream cause of the owner's bandwidth loss (hostile traffic vs congestion vs NetFend itself) | Audit shows NetFend's own blasting/scanning explains a large share (RC-1/2/3). After the rewrite, the dashboard's throughput/flood panels provide the measurements needed to attribute residual slowdowns. Next: run engine for a few days and review event history |
| U-2 | Whether the owner's Wi-Fi adapter/driver can expose management frames (deauth/disassoc) to userspace | Probe implemented (`iw phy` capability scan, `WifiDiagnostics.monitor_mode_capable`). Until probed on target hardware, frame-level deauth detection is reported unavailable; recommend enabling 802.11w/PMF on the AP |
| U-3 | Which DHCP server the owner's network actually uses (many home routers embed lease times that cause frequent renews) | DHCP guard learns the baseline server passively; first-run requires a learning window (default 2 observations) before flagging rogues — false-positive guard |
| U-4 | Whether the owner's system uses systemd-resolved, NetworkManager-resolved or plain resolv.conf | DNS guard watches the effective file (`resolvectl status` preferred when available, else /etc/resolv.conf); both paths implemented, verified only via unit fixtures |
| U-5 | Sandbox verification limits: no root, no nft, no systemd, no Wi-Fi in the development environment | All kernel-touching paths are exercised through unit tests with mocked command outputs; on-target verification commands are documented in README §Testing. Owner should run `sudo netfend doctor` on the real machine |
