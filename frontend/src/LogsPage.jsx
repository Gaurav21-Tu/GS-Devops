import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './LogsPage.css';

const API_BASE_URL = window.ENV?.REACT_APP_BASE_URL || 'http://10.26.30.175:32500';

function LogsPage() {
  const navigate = useNavigate();
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');
  
  

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchLogs = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/__admin/logs`);
      if (!response.ok) throw new Error('Failed to fetch logs');
      const data = await response.json();
      setLogs(data.logs || []);
      setLoading(false);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const filteredLogs = logs.filter(log =>
    log.message.toLowerCase().includes(filter.toLowerCase()) ||
    log.level.toLowerCase().includes(filter.toLowerCase())
  );

  const getLevelClass = (level) => {
    switch (level) {
      case 'ERROR': return 'level-error';
      case 'WARNING': return 'level-warning';
      case 'INFO': return 'level-info';
      default: return 'level-debug';
    }
  };

  if (loading) return <div className="loading">Loading logs...</div>;
  if (error) return <div className="error">Error: {error}</div>;

  return (
    <div className="logs-container">
      <header className="logs-header">
        <div className="header-left">
          <button onClick={() => navigate('/')} className="back-button">
            ← Back
          </button>
          <h1>Request Filter Logs</h1>
        </div>
        <div className="logs-stats">
          <span>Total: {logs.length}</span>
          <span>Filtered: {filteredLogs.length}</span>
        </div>
      </header>

      <div className="logs-controls">
        <input
          type="text"
          placeholder="Filter logs..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="filter-input"
        />
        <button onClick={fetchLogs} className="refresh-btn">
          Refresh
        </button>
      </div>

      <div className="logs-table-container">
        <table className="logs-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>Level</th>
              <th>Logger</th>
              <th>Message</th>
              <th>File</th>
              <th>Line</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map((log) => (
              <tr key={log.id} className={getLevelClass(log.level)}>
                <td>{log.id}</td>
                <td>{new Date(log.timestamp * 1000).toLocaleString()}</td>
                <td><span className={`level-badge ${getLevelClass(log.level)}`}>{log.level}</span></td>
                <td>{log.logger_name}</td>
                <td className="message-cell">{log.message}</td>
                <td>{log.filename}</td>
                <td>{log.line_number}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default LogsPage;
