import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";

function App() {
  const [config, setConfig] = useState({
    relays: [],
    interface_name: "",
    address: "",
    dns_servers: [],
  });
  const [status, setStatus] = useState("disconnected");
  const [relayInput, setRelayInput] = useState("");

  useEffect(() => {
    // Load config from backend
    invoke("load_config").then(setConfig);
    // Optionally, fetch relay status
    invoke("get_status").then(setStatus);
  }, []);

  const handleConfigChange = (e) => {
    setConfig({ ...config, [e.target.name]: e.target.value });
  };

  const handleRelayAdd = () => {
    if (relayInput) {
      setConfig({ ...config, relays: [...config.relays, relayInput] });
      setRelayInput("");
    }
  };

  const handleRelayRemove = (relay) => {
    setConfig({ ...config, relays: config.relays.filter((r) => r !== relay) });
  };

  const handleSave = () => {
    invoke("save_config", { config });
  };

  const handleConnect = () => {
    invoke("connect");
    setStatus("connected");
  };

  const handleDisconnect = () => {
    invoke("disconnect");
    setStatus("disconnected");
  };

  return (
    <div style={{ maxWidth: 600, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>AltNet Client UI</h1>
      <h2>Configuration</h2>
      <label>
        Interface Name:
        <input
          name="interface_name"
          value={config.interface_name}
          onChange={handleConfigChange}
        />
      </label>
      <br />
      <label>
        Address:
        <input
          name="address"
          value={config.address}
          onChange={handleConfigChange}
        />
      </label>
      <br />
      <label>
        DNS Servers (comma separated):
        <input
          name="dns_servers"
          value={config.dns_servers.join(",")}
          onChange={(e) =>
            setConfig({ ...config, dns_servers: e.target.value.split(",") })
          }
        />
      </label>
      <br />
      <h3>Relays</h3>
      <ul>
        {config.relays.map((relay, idx) => (
          <li key={idx}>
            {relay}{" "}
            <button onClick={() => handleRelayRemove(relay)}>Remove</button>
          </li>
        ))}
      </ul>
      <input
        value={relayInput}
        onChange={(e) => setRelayInput(e.target.value)}
        placeholder="Add relay address"
      />
      <button onClick={handleRelayAdd}>Add Relay</button>
      <br />
      <button onClick={handleSave}>Save Config</button>
      <h2>Status: {status}</h2>
      <button onClick={handleConnect} disabled={status === "connected"}>
        Connect
      </button>
      <button onClick={handleDisconnect} disabled={status === "disconnected"}>
        Disconnect
      </button>
    </div>
  );
}

export default App;
