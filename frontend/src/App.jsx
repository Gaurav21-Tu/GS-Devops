import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import HomePage from './HomePage';
import LogsPage from './LogsPage';
import AttackSimulator from './AttackSimulator';
import SettingsPage from './SettingsPage';
import './App.css';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/__admin/logs" element={<LogsPage />} />
        <Route path="/__admin/attack" element={<AttackSimulator />} />
        <Route path="/__admin/settings" element={<SettingsPage />} />
      </Routes>
    </Router>
  );
}

export default App;
