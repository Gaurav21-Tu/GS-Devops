import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './SettingsPage.css';

function SettingsPage() {
  const navigate = useNavigate();
  const [backendUrl, setBackendUrl] = useState('');
  const [defaultBackendUrl, setDefaultBackendUrl] = useState('');
  const [isCustom, setIsCustom] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    try {
      const response = await fetch('/__admin/config/backend');
      const data = await response.json();
      setBackendUrl(data.backend_url);
      setDefaultBackendUrl(data.default_backend_url);
      setIsCustom(data.is_custom);
      setLoading(false);
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to load configuration' });
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!backendUrl.trim()) {
      setMessage({ type: 'error', text: 'Backend URL cannot be empty' });
      return;
    }

    if (!backendUrl.startsWith('http://') && !backendUrl.startsWith('https://')) {
      setMessage({ type: 'error', text: 'Backend URL must start with http:// or https://' });
      return;
    }

    setSaving(true);
    setMessage(null);

    try {
      const response = await fetch('/__admin/config/backend', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ backend_url: backendUrl }),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage({ type: 'success', text: 'Backend URL updated successfully!' });
        setIsCustom(backendUrl !== defaultBackendUrl);
      } else {
        setMessage({ type: 'error', text: data.detail || 'Failed to update backend URL' });
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Error saving configuration' });
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setBackendUrl(defaultBackendUrl);
    setMessage(null);
  };

  if (loading) {
    return (
      <div className="settings-container">
        <div className="loading">Loading configuration...</div>
      </div>
    );
  }

  return (
    <div className="settings-container">
      <header className="settings-header">
        <div className="header-left">
          <button onClick={() => navigate('/')} className="back-button">
            ← Back
          </button>
          <h1>Settings</h1>
        </div>
      </header>

      <div className="settings-card">
        <h2>Backend Configuration</h2>
        
        <div className="config-section">
          <label>Target Backend URL:</label>
          <input
            type="text"
            className="backend-input"
            value={backendUrl}
            onChange={(e) => setBackendUrl(e.target.value)}
            disabled={saving}
            placeholder="http://backend.example.com:8080"
          />
          <small className="help-text">
            The backend service where filtered requests will be forwarded.
            {isCustom && <span className="custom-badge"> (Custom)</span>}
          </small>
        </div>

        <div className="config-section">
          <label>Default Backend URL:</label>
          <div className="default-url">{defaultBackendUrl}</div>
          <small className="help-text">
            The default backend URL from environment configuration
          </small>
        </div>

        {message && (
          <div className={`message ${message.type}`}>
            {message.type === 'success' ? '✅' : '❌'} {message.text}
          </div>
        )}

        <div className="button-group">
          <button
            className="save-button"
            onClick={handleSave}
            disabled={saving || backendUrl === ''}
          >
            {saving ? 'Saving...' : '💾 Save Configuration'}
          </button>
          <button
            className="reset-button"
            onClick={handleReset}
            disabled={saving}
          >
            🔄 Reset to Default
          </button>
        </div>
      </div>

      <div className="info-card">
        <h3>ℹ️ Important Notes</h3>
        <ul>
          <li>Changes take effect immediately for all new requests</li>
          <li>All filter instances will use the updated backend URL</li>
          <li>The configuration is stored in Redis and persists across pod restarts</li>
          <li>Make sure the backend URL is accessible from the filter pods</li>
        </ul>
      </div>
    </div>
  );
}

export default SettingsPage;
