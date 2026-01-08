import { useNavigate } from 'react-router-dom';
import './HomePage.css';

function HomePage() {
  const navigate = useNavigate();

  return (
    <div className="home-container">
      <div className="home-card">
        <h1>Request Filter Admin</h1>
        <p>Monitor and manage request filtering</p>
        
        <div className="button-grid">
          <button 
            className="nav-button logs-button"
            onClick={() => navigate('/__admin/logs')}
          >
            <span className="button-icon">📋</span>
            <span className="button-title">View Logs</span>
            <span className="button-desc">View application logs</span>
          </button>

          <button 
            className="nav-button attack-button"
            onClick={() => navigate('/__admin/attack')}
          >
            <span className="button-icon">⚔️</span>
            <span className="button-title">Attack Simulator</span>
            <span className="button-desc">Simulate attack requests</span>
          </button>

          <button 
            className="nav-button blocked-button"
            onClick={() => navigate('/__admin/blocked')}
          >
            <span className="button-icon">🚫</span>
            <span className="button-title">Blocked Requests</span>
            <span className="button-desc">View blocked fingerprints</span>
          </button>

          <button 
            className="nav-button stats-button"
            onClick={() => navigate('/__admin/stats')}
          >
            <span className="button-icon">📊</span>
            <span className="button-title">Statistics</span>
            <span className="button-desc">View request statistics</span>
          </button>

          <button 
            className="nav-button settings-button"
            onClick={() => navigate('/__admin/settings')}
          >
            <span className="button-icon">⚙️</span>
            <span className="button-title">Settings</span>
            <span className="button-desc">Configure backend and options</span>
          </button>
        </div>
      </div>
    </div>
  );
}

export default HomePage;
