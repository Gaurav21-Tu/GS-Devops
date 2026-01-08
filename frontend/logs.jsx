import { useState } from "react";

export default function LogsPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);

  const loadLogs = async () => {
    setLoading(true);
    const response = await fetch("http://10.26.30.175:32500/__admin/logs");
    const data = await response.json();
    setLogs(data);
    setLoading(false);
  };

  return (
    <div style={{ padding: "20px" }}>
      <h1>Application Logs</h1>

      <button 
        onClick={loadLogs} 
        style={{ padding: "10px 20px", marginBottom: "20px" }}>
        {loading ? "Loading..." : "View Logs"}
      </button>

      <table border="1" cellPadding="5" style={{ width: "100%" }}>
        <thead>
          <tr>
            <th>ID</th>
            <th>Timestamp</th>
            <th>Level</th>
            <th>Message</th>
            <th>Module</th>
            <th>Function</th>
          </tr>
        </thead>
        <tbody>
          {logs.map(log => (
            <tr key={log.id}>
              <td>{log.id}</td>
              <td>{log.timestamp}</td>
              <td>{log.level}</td>
              <td>{log.message}</td>
              <td>{log.module}</td>
              <td>{log.function}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
