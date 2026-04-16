from flask import Flask, render_template_string
from flask_socketio import SocketIO
import json
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import threading
import time

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

def analyze():
    with open("logs/packets.json", "r") as f:
        packets = json.load(f)

    rows = []
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        src   = layers.get("ip.src",           ["0.0.0.0"])[0]
        dst   = layers.get("ip.dst",           ["0.0.0.0"])[0]
        proto = layers.get("ip.proto",         ["0"])[0]
        size  = layers.get("frame.len",        ["0"])[0]
        delta = layers.get("frame.time_delta", ["0"])[0]
        rows.append({
            "src": src, "dst": dst,
            "proto": int(proto),
            "size": int(size),
            "time_delta": float(delta)
        })

    df = pd.DataFrame(rows)
    le_src = LabelEncoder()
    le_dst = LabelEncoder()
    df["src_encoded"] = le_src.fit_transform(df["src"])
    df["dst_encoded"] = le_dst.fit_transform(df["dst"])
    X = df[["src_encoded", "dst_encoded", "proto", "size", "time_delta"]]
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
    df["anomaly_score"] = model.decision_function(X)
    df["anomaly"]       = model.predict(X)
    return df

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IoT NIDS Live Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js"></script>
    <style>
        body { font-family: Arial; background: #0d1117; color: #c9d1d9; padding: 20px; }
        h1   { color: #58a6ff; }
        .cards { display: flex; gap: 20px; margin: 20px 0; }
        .card {
            background: #161b22; border-radius: 8px;
            padding: 20px; flex: 1; text-align: center;
            transition: all 0.3s ease;
        }
        .card h2 { font-size: 40px; margin: 0; }
        .card p  { color: #8b949e; margin: 5px 0 0 0; }
        .green { color: #3fb950; }
        .red   { color: #f85149; }
        .blue  { color: #58a6ff; }
        .live  {
            display: inline-block;
            width: 10px; height: 10px;
            background: #3fb950;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 1s infinite;
        }
        @keyframes pulse {
            0%   { opacity: 1; }
            50%  { opacity: 0.3; }
            100% { opacity: 1; }
        }
        table {
            width: 100%; border-collapse: collapse;
            background: #161b22; border-radius: 8px;
        }
        th { background: #21262d; padding: 12px; text-align: left; color: #58a6ff; }
        td { padding: 10px 12px; border-bottom: 1px solid #21262d; }
        tr.anomaly { background: #2d1616; }
        tr.normal  { background: #161b22; }
        .badge-red {
            background: #f85149; color: white;
            padding: 2px 8px; border-radius: 4px; font-size: 12px;
        }
        .badge-green {
            background: #3fb950; color: white;
            padding: 2px 8px; border-radius: 4px; font-size: 12px;
        }
        #last-updated { color: #8b949e; font-size: 13px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <h1><span class="live"></span>IoT Network Intrusion Detection — Live</h1>
    <div id="last-updated">Connecting...</div>

    <div class="cards">
        <div class="card"><h2 class="blue"  id="total">--</h2><p>Total Packets</p></div>
        <div class="card"><h2 class="green" id="normal">--</h2><p>Normal Packets</p></div>
        <div class="card"><h2 class="red"   id="anomalies">--</h2><p>Anomalies Detected</p></div>
    </div>

    <h2>📋 Packet Analysis</h2>
    <table>
        <thead>
            <tr>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Size (bytes)</th>
                <th>Score</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody id="packet-table"></tbody>
    </table>

    <script>
        const socket = io();

        socket.on("connect", () => {
            document.getElementById("last-updated").textContent = "Connected — waiting for data...";
        });

        socket.on("update", (data) => {
            // Update cards
            document.getElementById("total").textContent     = data.total;
            document.getElementById("normal").textContent    = data.normal;
            document.getElementById("anomalies").textContent = data.anomalies;

            // Update timestamp
            const now = new Date().toLocaleTimeString();
            document.getElementById("last-updated").textContent = "Last updated: " + now;

            // Update table
            const tbody = document.getElementById("packet-table");
            tbody.innerHTML = "";
            data.rows.forEach(row => {
                const tr = document.createElement("tr");
                tr.className = row.anomaly === -1 ? "anomaly" : "normal";
                const badge = row.anomaly === -1
                    ? '<span class="badge-red"> ANOMALY</span>'
                    : '<span class="badge-green"> NORMAL</span>';
                tr.innerHTML = `
                    <td>${row.src}</td>
                    <td>${row.dst}</td>
                    <td>${row.proto}</td>
                    <td>${row.size}</td>
                    <td>${row.score}</td>
                    <td>${badge}</td>
                `;
                tbody.appendChild(tr);
            });
        });
    </script>
</body>
</html>
"""

def push_updates():
    while True:
        try:
            df = analyze()
            rows = []
            for _, row in df.iterrows():
                proto_name = "ICMP" if row["proto"] == 1 else "ARP" if row["proto"] == 0 else str(int(row["proto"]))
                rows.append({
                    "src":     row["src"],
                    "dst":     row["dst"],
                    "proto":   proto_name,
                    "size":    int(row["size"]),
                    "score":   f"{row['anomaly_score']:.4f}",
                    "anomaly": int(row["anomaly"])
                })
            socketio.emit("update", {
                "total":     len(df),
                "normal":    len(df[df["anomaly"] ==  1]),
                "anomalies": len(df[df["anomaly"] == -1]),
                "rows":      rows
            })
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(5)

@app.route("/")
def index():
    return render_template_string(TEMPLATE)

if __name__ == "__main__":
    t = threading.Thread(target=push_updates, daemon=True)
    t.start()
    print("Live dashboard running!")
    print("Open: http://127.0.0.1:8000")
    socketio.run(app, host="127.0.0.1", port=8000, debug=False, allow_unsafe_werkzeug=True)