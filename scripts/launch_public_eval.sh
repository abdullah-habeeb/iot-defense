#!/bin/bash
# Output directories keep the names data/evaluation/pub3_{after,before}_{benign,small,large}: this is the third
# iteration; the earlier ones scored the two configurations with different matching windows and are superseded.
# Needs data/external/iot23/ (IoT-23, not redistributed; see README "What is and is not in git").
# Re-run the public-data evaluation with the corrected metrics (one 60 s scoring window for every configuration,
# named recall, firewall actions that respect the 60 s block). Two waves so the 2-vCPU VM is not overloaded.
cd ~/iot-defense || exit 1
D=data/external/iot23
export PYTHONPATH=src
PY=.venv/bin/python
E=iot_defense.evaluation.public_eval
SMALL="$D/m08.pcap=$D/m08.conn.log.labeled $D/m20.pcap=$D/m20.conn.log.labeled $D/m21.pcap=$D/m21.conn.log.labeled $D/m42.pcap=$D/m42.conn.log.labeled"
LARGE="$D/m34.pcap=$D/m34.conn.log.labeled $D/m03.pcap=$D/m03.conn.log.labeled"
rm -f /tmp/pub3.done
mkdir -p data/evaluation/pub3_after_benign data/evaluation/pub3_after_small data/evaluation/pub3_after_large data/evaluation/pub3_before_benign data/evaluation/pub3_before_small data/evaluation/pub3_before_large

# wave 1: the 60 s / both-directions configuration
nice -n 10 $PY -m $E --window 60 --directions both --match-window 60 --benign $D/benign_echo.pcap --output-dir data/evaluation/pub3_after_benign > /tmp/pub3_after_benign.out 2>&1 &
nice -n 10 $PY -m $E --window 60 --directions both --match-window 60 --malicious $SMALL --output-dir data/evaluation/pub3_after_small > /tmp/pub3_after_small.out 2>&1 &
nice -n 10 $PY -m $E --window 60 --directions both --match-window 60 --max-seconds 1800 --malicious $LARGE --output-dir data/evaluation/pub3_after_large > /tmp/pub3_after_large.out 2>&1 &
wait
# wave 2: the original 5 s / inbound configuration, scored with the same 60 s window
nice -n 10 $PY -m $E --window 5 --directions inbound --match-window 60 --benign $D/benign_echo.pcap --output-dir data/evaluation/pub3_before_benign > /tmp/pub3_before_benign.out 2>&1 &
nice -n 10 $PY -m $E --window 5 --directions inbound --match-window 60 --malicious $SMALL --output-dir data/evaluation/pub3_before_small > /tmp/pub3_before_small.out 2>&1 &
nice -n 10 $PY -m $E --window 5 --directions inbound --match-window 60 --max-seconds 1800 --malicious $LARGE --output-dir data/evaluation/pub3_before_large > /tmp/pub3_before_large.out 2>&1 &
wait
touch /tmp/pub3.done
