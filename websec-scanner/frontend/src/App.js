import React, { useState } from 'react';
import ScanForm from './components/ScanForm';
import ScanResults from './components/ScanResults';

function App() {
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async (url) => {
    setLoading(true);
    setError(null);
    setScanResults(null);
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url })
      });
      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`);
      }
      const data = await response.json();
      setScanResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App" style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>WebSec AI Scanner</h1>
      <ScanForm onScan={handleScan} />
      {loading && <p>Scanning in progress...</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
      {scanResults && <ScanResults results={scanResults} />}
    </div>
  );
}

export default App;
