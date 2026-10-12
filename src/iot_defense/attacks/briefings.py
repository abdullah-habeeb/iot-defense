"""Plain-language briefings for every registered attack.

The dashboard's "Attack Briefing" card shows one of these as soon as a
simulation starts, so someone new to security can read what the attack is,
what it does, and how this system notices it -- without reading the code.

The text lives here, next to the registry, and not in the front end, for one
reason: a briefing is only useful if it exists for every attack. A test
(tests/test_attack_briefings.py) fails if an attack is registered without
one, or a briefing outlives its attack, so adding an attack to the registry
cannot silently leave the dashboard card blank.

Facts that the registry already knows (which way the traffic flows, whether
the attack is spread over several sources) are not repeated in the text; they
are read from the registry by describe_attack(), so they cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from iot_defense.attacks.registry import ATTACK_SCENARIOS

ATTACKER_IP = "10.0.0.100"
SENSOR_IP = "10.0.0.10"


@dataclass(frozen=True)
class AttackBriefing:
    category: str
    """The family the attack belongs to, as a short badge."""
    summary: str
    """What it is, in one sentence, with an everyday comparison."""
    steps: tuple[str, str, str]
    """What happens, in order."""
    impact: str
    """What it does to a home network if nothing stops it."""
    tell: str
    """How this system recognises it, in plain words."""


BRIEFINGS: dict[str, AttackBriefing] = {
    "reconnaissance": AttackBriefing(
        category="Scouting",
        summary="Trying every door of a house to see which ones are unlocked, before deciding how to break in.",
        steps=(
            "The attacker's computer sends connection requests ('knocks') to many different ports on the target, one after another.",
            "Ports with a service listening answer; closed ones refuse. Every answer reveals what software the device runs.",
            "The attacker ends up with a map of open ports and picks the weakest one for a later attack.",
        ),
        impact="Nothing breaks yet, but this is usually the first step of a real attack, so catching it early buys time.",
        tell="One source touching many different ports at a moderate pace, mostly connection attempts that get refused.",
    ),
    "dos": AttackBriefing(
        category="Flooding (denial of service)",
        summary="Jamming a shop's phone line with nonstop calls so real customers can't get through.",
        steps=(
            "The attacker's computer fires a nonstop stream of UDP packets at one port on the target.",
            "The device has to spend its limited processing power and bandwidth on this junk.",
            "Real traffic, such as the camera reporting to the sensor, gets delayed or dropped.",
        ),
        impact="The device becomes slow or unreachable, so a smart-home sensor stops reporting.",
        tell="A very high packet rate from one source to one port, the opposite shape of a scan (many ports, slow pace).",
    ),
    "brute_force": AttackBriefing(
        category="Credential attack",
        summary="Trying one password after another on a lock until one finally fits.",
        steps=(
            "The attacker repeatedly opens a connection to the device's login port.",
            "Each attempt is a full connect-and-close with a short pause, like one password guess after the next.",
            "If any guess is right, the attacker gets in as a legitimate user.",
        ),
        impact="A weak or factory-default password gets guessed and the attacker takes over the device.",
        tell="Many connection attempts to one port at a steady, moderate pace with small packets: faster than a person, slower than a flood.",
    ),
    "exfiltration": AttackBriefing(
        category="Data theft",
        summary="A burglar who is already inside the house, carrying stolen items out the back door.",
        steps=(
            "A device on the network has already been compromised, so an attacker controls it.",
            "It sends unusually large packets (about 1200 bytes each) to a computer the attacker owns.",
            "Whatever the device holds, such as readings, images or credentials, leaves the home network.",
        ),
        impact="Private data is stolen, and because nothing looks broken the owner may never notice.",
        tell="The direction is reversed: the device itself sends a few unusually big packets outward to a single destination.",
    ),
    "exploit": AttackBriefing(
        category="Exploitation",
        summary="Using a known flaw in a device's software, like slipping a specially cut key into a faulty lock.",
        steps=(
            "The attacker makes just a few connections to the device's management port.",
            "Each one carries a single oversized, specially crafted message meant to trigger a software bug.",
            "If the bug exists, the attacker can make the device run their own commands.",
        ),
        impact="Complete takeover of the device.",
        tell="Very few packets, but each is unusually large and aimed at one port: the size of the payload, not the volume, gives it away.",
    ),
    "syn_flood": AttackBriefing(
        category="Flooding (denial of service)",
        summary="Ringing a doorbell thousands of times and never waiting for the door to open, so whoever answers is kept busy.",
        steps=(
            "The attacker sends a huge number of TCP connection starts (SYN packets) to one port.",
            "It never finishes the three-step handshake, so no real connection is ever made.",
            "The target keeps spending effort on connection attempts that lead nowhere.",
        ),
        impact="The device can run out of capacity for connections and stop answering genuine visitors.",
        tell="Lots of connection starts to a single port with no completed handshakes: faster than a scan and aimed at one port.",
    ),
    "icmp_flood": AttackBriefing(
        category="Flooding (denial of service)",
        summary="Sending a constant barrage of 'are you there?' pings until the line is saturated.",
        steps=(
            "The attacker uses ping to send echo requests to the device without pause.",
            "Each ping is padded with extra data (about 220 bytes), which makes the flood heavier.",
            "The device must answer every one, wasting its bandwidth and processing power.",
        ),
        impact="The device slows down or drops off the network.",
        tell="A stream of ICMP (ping) packets with no ports involved and a larger-than-normal size.",
    ),
    "slow_loris": AttackBriefing(
        category="Resource exhaustion (denial of service)",
        summary="Taking every seat in a restaurant and ordering nothing, so real customers have nowhere to sit.",
        steps=(
            "The attacker opens many connections at the same moment (about 28) to one port.",
            "Each connection sends a fragment of a request and then just stays open, never finishing.",
            "The device's limited connection slots fill up with these idle connections.",
        ),
        impact="Legitimate users are locked out even though almost no data is flowing.",
        tell="Many simultaneous connections from one source, each with its own source port, held open instead of closed.",
    ),
    "dns_amplification": AttackBriefing(
        category="Flooding (denial of service)",
        summary="Shouting a small question that makes a crowd send big answers to the victim.",
        steps=(
            "In the real world the attacker tricks DNS servers into sending large replies to a victim's address.",
            "The device then receives a steady stream of big UDP 'answers' (about 570 bytes each) it never asked for.",
            "These unrequested replies pile up and clog the device's connection.",
        ),
        impact="The device's bandwidth is used up by traffic it did not ask for, so it stops responding.",
        tell="A sustained stream of large UDP packets arriving at the device that it never requested.",
    ),
    "dns_tunneling": AttackBriefing(
        category="Data theft",
        summary="Smuggling secrets out of a building inside harmless-looking postcards.",
        steps=(
            "A compromised device cuts the data it wants to steal into small pieces and encodes them.",
            "Each piece is hidden inside what looks like a DNS lookup, a small UDP packet of about 220 bytes.",
            "Sent often over a long time, the pieces add up to a hidden channel that gets past firewalls that allow DNS.",
        ),
        impact="Data leaks slowly and quietly, past simple defences.",
        tell="Outward traffic made of many small, frequent UDP packets over a long window: the 'low and slow' opposite of exfiltration's few big packets.",
    ),
    "mqtt_flood": AttackBriefing(
        category="Flooding (denial of service)",
        summary="Burying a smart home's message board under so many tiny notes that the real messages get lost.",
        steps=(
            "MQTT is the messaging protocol many smart devices use. The attacker opens a great many connections to the device's MQTT port.",
            "Every connection completes properly and delivers one small message.",
            "The device has to process every connection and message, one after the other.",
        ),
        impact="Messages from real sensors and switches are delayed or lost, so automations stop working.",
        tell="Many fully completed connections to the MQTT port in a short time, unlike a SYN flood where handshakes never finish.",
    ),
    "firmware_tampering": AttackBriefing(
        category="Malware control",
        summary="A rogue employee quietly sending out or altering the company's settings records.",
        steps=(
            "A device has already been compromised and is under the attacker's control.",
            "At intervals it sends medium-sized blobs of configuration or firmware data to an outside host, at a slow steady pace.",
            "Settings can leak (for example Wi-Fi passwords) or be replaced with ones the attacker chose.",
        ),
        impact="The attacker keeps their grip on the device, and its trusted settings can no longer be relied on.",
        tell="Outward traffic of medium-sized packets at a slow, steady rate: bigger than DNS tunneling, slower than a beacon.",
    ),
    "buffer_overflow": AttackBriefing(
        category="Exploitation",
        summary="Stuffing far more into a box than it can hold, until it bursts and spills into things it should never touch.",
        steps=(
            "The attacker opens a single connection to the device.",
            "Over it they send one oversized message after another, trying to find input the software mishandles.",
            "A badly written program may crash or, worse, start running code the attacker supplied.",
        ),
        impact="The device crashes and reboots, or is taken over.",
        tell="A long run of large packets down one persistent connection: unlike a one-shot exploit, it keeps going.",
    ),
    "replay_attack": AttackBriefing(
        category="Credential attack",
        summary="Recording the signal of a car key fob and playing it back later to open the car.",
        steps=(
            "The attacker has captured a valid login or command message from earlier.",
            "They send exactly the same message again and again to the device.",
            "The device cannot tell the copy from the genuine one, so it may obey it, for example by switching a plug on or off.",
        ),
        impact="Commands run without the attacker ever knowing the password.",
        tell="The same message repeated rapidly to one port over UDP.",
    ),
    "rogue_beacon": AttackBriefing(
        category="Malware control",
        summary="A hidden bug planted on a device that keeps phoning its owner with updates.",
        steps=(
            "A compromised device keeps sending small status and configuration messages to an outside host.",
            "They leave frequently (more than 5 per second), far more often than normal device chatter.",
            "This tells the attacker the implant is alive and lets them steer it.",
        ),
        impact="The attacker keeps live, ongoing control of a device inside the home.",
        tell="Small outward packets at a high steady frequency: the busier cousin of firmware tampering.",
    ),
    "c2_beacon": AttackBriefing(
        category="Malware control",
        summary="A spy checking in with headquarters at exactly the same time every day.",
        steps=(
            "A compromised device contacts a fixed outside server, known as a command-and-control server.",
            "It does so on a near-perfectly regular schedule.",
            "Each check-in asks 'any orders?', and the reply can tell it to steal data or attack others.",
        ),
        impact="The device becomes part of a botnet, a network of hijacked machines run by the attacker.",
        tell="The timing: the gaps between check-ins are almost identical, which people and normal apps rarely produce.",
    ),
    "dos_distributed": AttackBriefing(
        category="Flooding (denial of service)",
        summary="The same flood as a DDoS, but the junk seems to come from many places at once, like a crowd instead of one person.",
        steps=(
            "The attacker's computer sends the flood using several source addresses: its own plus forged (spoofed) ones.",
            "Each address sends only a modest share, small enough to look harmless on its own.",
            "Together they overwhelm the target, and blocking any single address barely helps.",
        ),
        impact="The same slowdown or outage as a DDoS, but harder to stop by blocking one sender.",
        tell="No single address looks guilty, so the system counts how many different sources are hitting the same target at once.",
    ),
    "syn_flood_distributed": AttackBriefing(
        category="Flooding (denial of service)",
        summary="The doorbell flood again, but the rings seem to come from many different people.",
        steps=(
            "The attacker sends connection starts (SYN packets) with several forged source addresses.",
            "Only the first step of each connection is sent. A handshake cannot finish toward a forged address anyway.",
            "The target keeps wasting effort on all of them, and no one address stands out.",
        ),
        impact="The device runs out of capacity for connections while the traffic looks like it comes from a crowd.",
        tell="Many different sources each starting connections to the same target port, with none completing.",
    ),
    "icmp_flood_distributed": AttackBriefing(
        category="Flooding (denial of service)",
        summary="A ping barrage that seems to come from many different machines at once.",
        steps=(
            "The attacker sends ping requests that carry several forged source addresses.",
            "Each address contributes only a share of the traffic, so each looks harmless alone.",
            "Together they saturate the device while hiding who is really behind it.",
        ),
        impact="The device slows down or drops off the network, and blocking one address does not stop it.",
        tell="Many different sources sending ping packets to the same target at the same time.",
    ),
    "replay_distributed": AttackBriefing(
        category="Credential attack",
        summary="A recorded command played back again and again, but made to look like it comes from many different senders.",
        steps=(
            "The attacker has a captured login or command message.",
            "They replay it over UDP, which makes forged source addresses easy, so it seems to arrive from several senders.",
            "The device may obey the repeated copies, and no single sender can be pinned down.",
        ),
        impact="Commands run without a password, and the source is harder to block.",
        tell="Many different sources sending the same repeated message to one port on the same target.",
    ),
}


def describe_attack(key: str) -> dict[str, Any]:
    """Everything the dashboard card shows for one attack: the hand-written
    text plus the facts read from the registry."""
    scenario = ATTACK_SCENARIOS[key]
    briefing = BRIEFINGS[key]
    outbound = scenario.traffic_direction == "outbound"
    sources = len(scenario.sender_ips) if scenario.sender_ips else 1
    distributed = sources > 1

    if outbound:
        lab_note = (
            f"The sensor ({SENSOR_IP}) plays a device that has already been compromised "
            f"and sends traffic out to the attacker's machine ({ATTACKER_IP})."
        )
    elif distributed:
        lab_note = (
            f"The attacker ({ATTACKER_IP}) sends traffic to the sensor ({SENSOR_IP}) using {sources} source "
            f"addresses: its own plus {sources - 1} forged ones."
        )
    else:
        lab_note = f"The attacker ({ATTACKER_IP}) sends traffic to the sensor ({SENSOR_IP})."

    return {
        "key": key,
        "label": scenario.label,
        "category": briefing.category,
        "summary": briefing.summary,
        "steps": list(briefing.steps),
        "impact": briefing.impact,
        "tell": briefing.tell,
        "direction": scenario.traffic_direction,
        "distributed": distributed,
        "sources": sources,
        "lab_note": lab_note,
    }
