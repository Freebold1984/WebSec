import React, { useState } from 'react';

function ScanForm({ onScan }) {
  const [url, setUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      onScan(url.trim());
    }
  };

  return (
    <form onSubmit={handleSubmit} style={{ marginBottom: '20px' }}>
      <input
        type="url"
        placeholder="Enter target URL"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        required
        style={{ width: '300px', padding: '8px', fontSize: '16px' }}
      />
      <button type="submit" style={{ marginLeft: '10px', padding: '8px 16px', fontSize: '16px' }}>
        Start Scan
      </button>
    </form>
  );
}

export default ScanForm;
