# ShieldNet

I built ShieldNet to learn how real network intrusion detection systems work,
not just the theory, but actually capturing packets, training a model on them, 
and watching it catch attacks in real time.

## What it does

ShieldNet watches network traffic from IoT devices and raises an alert when 
something looks suspicious. It uses two approaches together:

- **Suricata** handles the known attack patterns like ping 
  floods, port scans, and brute force attempts
- **A machine learning model** handles everything else. It learns what normal 
  traffic looks like, then flags anything that deviates from that baseline

The results show up on a live dashboard that updates every 5 seconds.

## How I built it

I didn't have real IoT devices, so I simulated a small network using Docker, 
a security camera, a thermostat, and a smart bulb, each with their own IP 
address, each behaving the way a real device would.

From there I captured the traffic with tcpdump, extracted packet features 
(source/destination IP, protocol, size, timing), and trained an Isolation 
Forest model on the normal traffic. Then I simulated a ping flood attack and 
watched the model flag 205 anomalies out of 4089 packets automatically with 
no manual rules.

## Running it locally

```bash
# Clone the repo
git clone https://github.com/YacoubaCamara/ShieldNet.git
cd ShieldNet

# Set up Python
python3 -m venv venv
source venv/bin/activate
pip install pandas scikit-learn flask flask-socketio gevent

# Start the simulated IoT network
docker network create --driver bridge --subnet 192.168.100.0/24 iot-network
docker compose up -d

# Terminal 1 — capture traffic
docker run --rm --net container:iot-camera --cap-add NET_ADMIN --cap-add NET_RAW \
  -v $(pwd)/logs:/logs nicolaka/netshoot tcpdump -i eth0 -n -w /logs/capture.pcap

# Terminal 2 — simulate a ping flood attack
docker exec iot-camera ping -c 1000 -i 0.001 192.168.100.11

# Terminal 3 — export packets and update dashboard
docker run --rm -v $(pwd)/logs:/logs nicolaka/netshoot tshark \
  -r /logs/capture.pcap -T json \
  -e ip.src -e ip.dst -e ip.proto -e frame.len -e frame.time_delta \
  > logs/packets.json

# Start the live dashboard
python3 ml/dashboard.py
```

## Tech

Python, Flask, WebSockets, Docker, Suricata, scikit-learn, tcpdump, tshark

## What I learned

Setting up packet capture on Mac with Docker was the trickiest part. Docker 
Desktop hides the bridge interfaces inside a Linux VM, so tcpdump can't access 
them directly. The fix was to run tcpdump inside a container on the same 
network namespace as the device being monitored.

The ML side was surprisingly straightforward once the data was clean. Isolation 
Forest works really well for anomaly detection because you don't need labeled 
attack data, you just need enough normal traffic to establish a threshold. 
