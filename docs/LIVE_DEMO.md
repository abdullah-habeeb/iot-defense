# Live demo: defending a real device on a real network

This runs the same detectors, three policies and arbiter as the lab, but on real packets from real
devices, and applies the chosen response as a real firewall rule.

```
 [Attacker laptop]  --Wi-Fi-->  [Protected box = VirtualBox VM running this system]  <--Wi-Fi--  [Phone]
   one nmap command              watches, detects, decides, blocks                       keeps loading a page
                                         |
                                  [Dashboard at http://localhost:8000]
```

Only use your own devices, on a network you control (a phone hotspot or home router), never college
or public Wi-Fi, and never point the attacker at anyone else's device.

## 1. One-time setup

**VirtualBox.** Shut the VM down. Settings, Network, **Adapter 2**: Enable, *Attached to* **Bridged
Adapter**, *Name* the laptop's Wi-Fi adapter, and under Advanced set *Promiscuous Mode* to
*Allow All*. Leave Adapter 1 (NAT) alone: it carries the SSH tunnel. Start the VM.

**Find the interface.** In the VM: `ip -4 -br addr`. The bridged adapter is the one with an address
on your hotspot's network (for example `enp0s8  192.168.43.10/24`). That name is `--iface` below.

**Attacker laptop.** Install `nmap` from nmap.org.

**Phone.** Nothing to install.

All three devices must be on the same Wi-Fi. Check the phone can reach the box:
`ping <box-ip>` from the attacker laptop. If devices cannot reach each other the network has
*client isolation* turned on (common on campus and public Wi-Fi); use a phone hotspot instead.

## 2. Before the demo: prove it works without hardware

```bash
cd ~/iot-defense
sudo bash scripts/live_selftest.sh
```

This builds a tiny virtual network inside the VM, with a pretend attacker and a pretend phone, and
checks detection, blocking, no harm to the phone, automatic expiry and clean-up with real packets and
real `iptables`. It must end with `SELF-TEST PASSED`.

## 3. Before the demo: calibrate on normal traffic

Start recording. It serves the same page the demo does, so as soon as it says so, open
`http://<box-ip>:8080` on the phone and leave it open for the two minutes:

```bash
sudo .venv/bin/python3 -m iot_defense.live.defender calibrate --iface enp0s8 --seconds 120
```

It must end with `OK: nothing the defender would act on`. A flagged check that lasts one second is normal (the first
packets of any new client look unusual for a moment) and is not a problem; only runs of consecutive flagged checks
count, and a device that completed real requests to the page is never acted on. If it says `NO TRUSTED DEVICE`, the
phone never loaded the page: run it again with the page open. If it says `FALSE ALARM from an untrusted source`, do
not demo until the cause is understood.

## 4. Demo

**Terminal on the VM** (leave running):

```bash
cd ~/iot-defense
sudo .venv/bin/python3 -m iot_defense.live.defender run --iface enp0s8
```

Open the dashboard at http://localhost:8000 and choose the **Live Physical Demo** tab (http://localhost:8000/live).
It has its own state, separate from the **Mininet Simulation** tab, and shows whether the defender is running.
Its *Run the demo* panel lists these commands with copy buttons. On the phone open `http://<box-ip>:8080`: it shows
**ONLINE** and refreshes by itself. After two replies the box trusts the phone as a normal user.

**On the attacker laptop:**

```
nmap -sT -p 1-1000 <box-ip>
```

What happens, in order:

| Time | What you see |
|---|---|
| 0 s | The scan starts. |
| 1 to 3 s | Dashboard: *Threat detected: Reconnaissance (port scan)*, with the attacker's address. |
| 3 to 4 s | Three advisors propose; the arbiter picks **BLOCK_SOURCE**. The Rule-based advisor's DECOY is shown as not available on this device. |
| 4 to 5 s | *Active firewall rules* shows the attacker's address and a rising dropped-packet counter. |
| after | nmap stalls and reports ports as `filtered`. The phone page stays **ONLINE**. |
| 60 s | The rule expires by itself; the dashboard says so. |

Stop with Ctrl+C: every firewall rule the tool added is removed.

## 5. Safety

* All rules live in one chain, `IOTDEF`, hooked only to the interface you name. The NAT adapter that
  carries SSH is never touched.
* The box itself, the Wi-Fi gateway, anything in `--allow`, and any device that completes real
  requests to the page are never blocked.
* Every block expires after `--ttl` seconds (default 60) by timer and, where the kernel supports it,
  in the rule itself.
* A response needs two consecutive detections, so a one-off coincidence of normal traffic changes nothing.
* If anything goes wrong: `sudo .venv/bin/python3 -m iot_defense.live.defender restore --iface enp0s8`
  removes everything, or reboot the VM.
* `--dry-run` prints the firewall commands instead of running them.

## 6. What is and is not claimed

* It protects the one machine it runs on (like a smart-home hub), not a whole home network.
* Detection covers traffic *to* the box, over IPv4. IPv6 and outbound attacks (exfiltration, beacons)
  are not handled live.
* The responses available here are ALLOW, ALERT, FORENSIC_CAPTURE, BLOCK_SOURCE and THROTTLE. A
  policy that proposes something else (a decoy needs a second machine) is set aside and the dashboard
  says so.
* The arbiter's track record comes from the lab measurements. Here it is applied, not re-measured.
* The detector thresholds were tuned on lab traffic. That is why step 3 exists.
