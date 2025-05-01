import React from 'react';

const ScanResults = ({ results }) => {
  if (!results) {
    return null;
  }

  const riskScore = results?.risk_score ?? 0;

  return (
    <div>
      <h2>Scan Results</h2>
      <p>Risk Score: {riskScore.toFixed(2)}</p>
      {results.vulnerabilities && results.vulnerabilities.length > 0 ? (
        <ul>
          {results.vulnerabilities.map((vuln, index) => (
            <li key={index}>
              <strong>Type:</strong> {vuln.type} <br />
              <strong>Risk Score:</strong> {vuln.risk_score} <br />
              <strong>Payload:</strong> {vuln.payload} <br />
              <strong>Recommendation:</strong> {vuln.recommendation}
            </li>
          ))}
        </ul>
      ) : (
        <p>No vulnerabilities found.</p>
      )}
    </div>
  );
};

export default ScanResults;
