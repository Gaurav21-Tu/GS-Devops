import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './AttackSimulator.css';

function AttackSimulator() {
  const navigate = useNavigate();
  const [selectedMethods, setSelectedMethods] = useState(['GET']);
  const [filterUrl, setFilterUrl] = useState('http://10.26.30.175:32500');
  const [targetPath, setTargetPath] = useState('/');
  const [attackSize, setAttackSize] = useState(10);
  const [isAttacking, setIsAttacking] = useState(false);
  const [results, setResults] = useState([]);
  const [summary, setSummary] = useState(null);

  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];

  const handleMethodToggle = (method) => {
    if (selectedMethods.includes(method)) {
      setSelectedMethods(selectedMethods.filter(m => m !== method));
    } else {
      setSelectedMethods([...selectedMethods, method]);
    }
  };

  const simulateAttack = async () => {
    if (selectedMethods.length === 0) {
      alert('Please select at least one method');
      return;
    }

    setIsAttacking(true);
    setResults([]);
    setSummary(null);

    const newResults = [];
    let successCount = 0;
    let blockedCount = 0;

    // Construct full URL from filter URL + target path
    const fullUrl = filterUrl.replace(/\/$/, '') + (targetPath.startsWith('/') ? targetPath : '/' + targetPath);

    // Create array of promises for concurrent execution
    const requests = [];
    for (let i = 0; i < attackSize; i++) {
      const method = selectedMethods[Math.floor(Math.random() * selectedMethods.length)];
      const requestId = i + 1;
      
      const requestPromise = fetch(fullUrl, {
        method: method,
        headers: {
          'Content-Type': 'application/json',
        },
      })
        .then(response => ({
          id: requestId,
          method: method,
          status: response.status,
          blocked: response.status === 403,
          timestamp: new Date().toLocaleTimeString()
        }))
        .catch(error => ({
          id: requestId,
          method: method,
          status: 'Error',
          blocked: false,
          timestamp: new Date().toLocaleTimeString(),
          error: error.message
        }));
      
      requests.push(requestPromise);
    }

    // Execute all requests concurrently
    const results = await Promise.all(requests);
    
    // Process results
    results.forEach(result => {
      if (result.status === 403) {
        blockedCount++;
      } else if (result.status >= 200 && result.status < 300) {
        successCount++;
      }
      newResults.push(result);
    });

    setResults(newResults);
    setSummary({
      total: attackSize,
      success: successCount,
      blocked: blockedCount,
      failed: attackSize - successCount - blockedCount
    });

    setIsAttacking(false);
  };

  return (
    <div className="attack-container">
      <header className="attack-header">
        <div className="header-left">
          <button onClick={() => navigate('/')} className="back-button">
            ← Back
          </button>
          <h1>Attack Simulator</h1>
        </div>
      </header>

      <div className="attack-config-card">
        <h2>Attack Configuration</h2>
        
        <div className="config-section">
          <label>Select HTTP Methods:</label>
          <div className="methods-grid">
            {methods.map(method => (
              <label key={method} className="method-checkbox">
                <input
                  type="checkbox"
                  checked={selectedMethods.includes(method)}
                  onChange={() => handleMethodToggle(method)}
                  disabled={isAttacking}
                />
                <span className={`method-badge ${method.toLowerCase()}`}>{method}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="config-section">
          <label>Filter URL (Request Filter Endpoint):</label>
          <input
            type="text"
            className="url-input"
            value={filterUrl}
            onChange={(e) => setFilterUrl(e.target.value)}
            disabled={isAttacking}
            placeholder="http://10.26.30.175:32500"
          />
          <small>The request filter endpoint (port 32500)</small>
        </div>

        <div className="config-section">
          <label>Target Path:</label>
          <input
            type="text"
            className="url-input"
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
            disabled={isAttacking}
            placeholder="/"
          />
          <small>The path that will be forwarded to the backend (e.g., /api/users)</small>
        </div>

        <div className="config-section">
          <label>Attack Size (Number of Requests):</label>
          <input
            type="number"
            className="size-input"
            value={attackSize}
            onChange={(e) => setAttackSize(Math.max(1, Math.min(10000, parseInt(e.target.value) || 1)))}
            disabled={isAttacking}
            min="1"
            max="10000"
          />
          <small>Maximum 10000 requests</small>
        </div>

        <button
          className="send-attack-button"
          onClick={simulateAttack}
          disabled={isAttacking || selectedMethods.length === 0}
        >
          {isAttacking ? 'Attacking...' : '🚀 Send Attack'}
        </button>
      </div>

      {summary && (
        <div className="summary-card">
          <h3>Attack Summary</h3>
          <div className="summary-stats">
            <div className="stat-item total">
              <span className="stat-label">Total Requests</span>
              <span className="stat-value">{summary.total}</span>
            </div>
            <div className="stat-item success">
              <span className="stat-label">Successful (200)</span>
              <span className="stat-value">{summary.success}</span>
            </div>
            <div className="stat-item blocked">
              <span className="stat-label">Blocked (403)</span>
              <span className="stat-value">{summary.blocked}</span>
            </div>
            <div className="stat-item failed">
              <span className="stat-label">Failed/Error</span>
              <span className="stat-value">{summary.failed}</span>
            </div>
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className="results-card">
          <h3>Attack Results</h3>
          <div className="results-table-container">
            <table className="results-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Method</th>
                  <th>Status</th>
                  <th>Result</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {results.map(result => (
                  <tr key={result.id} className={result.blocked ? 'blocked-row' : result.status >= 200 && result.status < 300 ? 'success-row' : 'error-row'}>
                    <td>{result.id}</td>
                    <td><span className={`method-badge ${result.method.toLowerCase()}`}>{result.method}</span></td>
                    <td><span className="status-badge">{result.status}</span></td>
                    <td>
                      {result.blocked ? (
                        <span className="result-blocked">🚫 Blocked</span>
                      ) : result.status >= 200 && result.status < 300 ? (
                        <span className="result-success">✅ Success</span>
                      ) : (
                        <span className="result-error">❌ Error</span>
                      )}
                    </td>
                    <td>{result.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default AttackSimulator;
