import json
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

print("=== IoT Network Anomaly Detector ===\n")


print("[1] Reading packets from JSON file...")

with open("logs/packets.json", "r") as f:
    packets = json.load(f)

print(f"    Found {len(packets)} packets\n")


print("[2] Building feature table...")

rows = []
for pkt in packets:
    layers = pkt.get("_source", {}).get("layers", {})
    src   = layers.get("ip.src",          ["0.0.0.0"])[0]
    dst   = layers.get("ip.dst",          ["0.0.0.0"])[0]
    proto = layers.get("ip.proto",        ["0"])[0]
    size  = layers.get("frame.len",       ["0"])[0]
    delta = layers.get("frame.time_delta",["0"])[0]
    rows.append({
        "src":        src,
        "dst":        dst,
        "proto":      int(proto),
        "size":       int(size),
        "time_delta": float(delta)
    })

df = pd.DataFrame(rows)
print(f"    Shape: {df.shape}")
print(df.head())
print()


print("[3] Encoding data for ML model...")

le_src = LabelEncoder()
le_dst = LabelEncoder()
df["src_encoded"] = le_src.fit_transform(df["src"])
df["dst_encoded"] = le_dst.fit_transform(df["dst"])

features = ["src_encoded", "dst_encoded", "proto", "size", "time_delta"]
X = df[features]


print("[4] Training anomaly detection model...")

model = IsolationForest(contamination=0.05, random_state=42)
model.fit(X)
print("    Model trained!\n")


print("[5] Scoring packets...")

df["anomaly_score"] = model.decision_function(X)
df["anomaly"]       = model.predict(X)

normal    = df[df["anomaly"] ==  1]
anomalies = df[df["anomaly"] == -1]

print(f"    Normal packets:    {len(normal)}")
print(f"    Anomalous packets: {len(anomalies)}\n")


print("=" * 50)
print("ANOMALY DETECTION RESULTS")
print("=" * 50)

if len(anomalies) == 0:
    print(" No anomalies detected — traffic looks normal!")
else:
    print(f"  {len(anomalies)} suspicious packets detected:\n")
    for idx, row in anomalies.iterrows():
        src = le_src.inverse_transform([int(row["src_encoded"])])[0]
        dst = le_dst.inverse_transform([int(row["dst_encoded"])])[0]
        print(f"  {src} → {dst} | size={int(row['size'])}B | score={row['anomaly_score']:.4f}")

print()
print(" Analysis complete!")