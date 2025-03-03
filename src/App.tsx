import React, { useState, useEffect } from 'react';
import { Search, Shield, AlertTriangle, FileText, Terminal, ExternalLink, Cpu, Globe, Lock, Database } from 'lucide-react';

function App() {
  const [target, setTarget] = useState('');
  const [threads, setThreads] = useState(5);
  const [timeout, setTimeout] = useState(10);
  const [depth, setDepth] = useState(2);
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [reports, setReports] = useState([]);
  const [error, setError] = useState('');

  // Fetch available reports on component mount
  useEffect(() => {
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const response = await fetch('/api/reports');
      if (response.ok) {
        const data = await response.json();
        setReports(data);
      } else {
        console.error('Failed to fetch reports');
      }
    } catch (err) {
      console.error('Error fetching reports:', err);
    }
  };

  const handleScan = async () => {
    if (!target) {
      setError('Target URL is required');
      return;
    }

    setError('');
    setIsScanning(true);
    
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target,
          threads,
          timeout,
          depth
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setScanResults(data);
        setActiveTab('results');
        // Refresh the reports list
        fetchReports();
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Scan failed');
      }
    } catch (err) {
      setError('Network error. Is the API server running?');
      console.error('Error during scan:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const renderDashboard = () => (
    <div className="p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">BlackWidow Scanner</h2>
      
      {error && (
        <div className="mb-4 bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          <p>{error}</p>
        </div>
      )}
      
      <div className="mb-6">
        <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="target">
          Target URL or IP
        </label>
        <div className="flex">
          <input
            id="target"
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="shadow appearance-none border rounded-l w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
          />
          <button
            onClick={handleScan}
            disabled={!target || isScanning}
            className={`bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-r focus:outline-none focus:shadow-outline flex items-center ${!target || isScanning ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isScanning ? (
              <>
                <span className="animate-spin mr-2">⏳</span>
                Scanning...
              </>
            ) : (
              <>
                <Search className="w-4 h-4 mr-2" />
                Scan
              </>
            )}
          </button>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div>
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="threads">
            Threads: {threads}
          </label>
          <input
            id="threads"
            type="range"
            min="1"
            max="20"
            value={threads}
            onChange={(e) => setThreads(parseInt(e.target.value))}
            className="w-full"
          />
        </div>
        
        <div>
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="timeout">
            Timeout: {timeout}s
          </label>
          <input
            id="timeout"
            type="range"
            min="1"
            max="30"
            value={timeout}
            onChange={(e) => setTimeout(parseInt(e.target.value))}
            className="w-full"
          />
        </div>
        
        <div>
          <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="depth">
            Crawl Depth: {depth}
          </label>
          <input
            id="depth"
            type="range"
            min="1"
            max="5"
            value={depth}
            onChange={(e) => setDepth(parseInt(e.target.value))}
            className="w-full"
          />
        </div>
      </div>
      
      <div className="bg-gray-100 p-4 rounded-lg">
        <h3 className="text-lg font-semibold mb-2 text-gray-700">Command Preview:</h3>
        <div className="bg-gray-800 text-green-400 p-3 rounded font-mono text-sm overflow-x-auto">
          python blackwidow.py {target || 'https://target-website.com'} --threads {threads} --timeout {timeout} --depth {depth}
        </div>
      </div>

      {reports.length > 0 && (
        <div className="mt-6">
          <h3 className="text-lg font-semibold mb-2 text-gray-700">Previous Reports:</h3>
          <div className="bg-gray-100 p-4 rounded-lg">
            <ul className="divide-y divide-gray-200">
              {reports.map((report, index) => (
                <li key={index} className="py-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600">
                      {new Date(report.timestamp).toLocaleString()}
                    </span>
                    <a 
                      href={`/reports/${report.filename}`} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:text-blue-800 text-sm flex items-center"
                    >
                      View Report <ExternalLink className="w-3 h-3 ml-1" />
                    </a>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );

  const renderResults = () => {
    if (!scanResults) return null;
    
    return (
      <div className="p-6 bg-white rounded-lg shadow-md">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-800">Scan Results</h2>
          <div className="text-sm text-gray-500">
            {new Date(scanResults.timestamp).toLocaleString()}
          </div>
        </div>
        
        <div className="mb-6">
          <h3 className="text-lg font-semibold mb-2 flex items-center text-gray-700">
            <Globe className="w-5 h-5 mr-2" />
            Target: {scanResults.target}
          </h3>
        </div>
        
        {scanResults.report_file && (
          <div className="mb-6 bg-blue-50 p-4 rounded-lg">
            <p className="text-blue-700">
              A detailed report has been generated. 
              <a 
                href={`/reports/${scanResults.report_file}`} 
                target="_blank" 
                rel="noopener noreferrer"
                className="ml-2 text-blue-600 hover:text-blue-800 underline"
              >
                View Full Report
              </a>
            </p>
          </div>
        )}
        
        {scanResults.ssl_check && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-gray-50 p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-3 flex items-center text-gray-700">
                <Lock className="w-5 h-5 mr-2" />
                SSL/TLS Configuration
              </h3>
              <div className={`text-sm ${scanResults.ssl_check[0] ? 'text-green-600' : 'text-red-600'}`}>
                Status: {scanResults.ssl_check[0] ? 'Valid' : 'Invalid'}
              </div>
              <div className="text-sm mt-2">
                {scanResults.ssl_check[1] && typeof scanResults.ssl_check[1] === 'object' && scanResults.ssl_check[1].issuer && (
                  <div>Issuer: {scanResults.ssl_check[1].issuer}</div>
                )}
                {scanResults.ssl_check[1] && typeof scanResults.ssl_check[1] === 'object' && scanResults.ssl_check[1].expires && (
                  <div>Expires: {scanResults.ssl_check[1].expires}</div>
                )}
              </div>
            </div>
            
            {scanResults.missing_headers && (
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-lg font-semibold mb-3 flex items-center text-gray-700">
                  <Shield className="w-5 h-5 mr-2" />
                  Security Headers
                </h3>
                {scanResults.missing_headers.length > 0 ? (
                  <ul className="text-sm text-red-600">
                    {scanResults.missing_headers.map((header, index) => (
                      <li key={index} className="mb-1">• {header}</li>
                    ))}
                  </ul>
                ) : (
                  <div className="text-sm text-green-600">All security headers properly configured</div>
                )}
              </div>
            )}
          </div>
        )}
        
        {scanResults.open_ports && scanResults.vulnerable_paths && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-gray-50 p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-3 flex items-center text-gray-700">
                <Cpu className="w-5 h-5 mr-2" />
                Open Ports
              </h3>
              <div className="flex flex-wrap gap-2">
                {scanResults.open_ports.map((port, index) => (
                  <span key={index} className="bg-blue-100 text-blue-800 text-xs font-semibold px-2.5 py-0.5 rounded">
                    {port}
                  </span>
                ))}
              </div>
            </div>
            
            <div className="bg-gray-50 p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-3 flex items-center text-gray-700">
                <FileText className="w-5 h-5 mr-2" />
                Sensitive Paths
              </h3>
              <ul className="text-sm">
                {scanResults.vulnerable_paths.map((path, index) => (
                  <li key={index} className="mb-1 flex items-center">
                    <span className={`w-3 h-3 rounded-full mr-2 ${path[1] === 200 ? 'bg-red-500' : path[1] === 403 ? 'bg-yellow-500' : 'bg-gray-500'}`}></span>
                    {path[0]} <span className="text-gray-500 ml-2">(Status: {path[1]})</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
        
        {scanResults.vulnerabilities && (
          <div className="bg-gray-50 p-4 rounded-lg mb-6">
            <h3 className="text-lg font-semibold mb-3 flex items-center text-gray-700">
              <AlertTriangle className="w-5 h-5 mr-2" />
              Detected Vulnerabilities
            </h3>
            {scanResults.vulnerabilities.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="min-w-full bg-white">
                  <thead>
                    <tr>
                      <th className="py-2 px-4 border-b border-gray-200 bg-gray-100 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                        Type
                      </th>
                      <th className="py-2 px-4 border-b border-gray-200 bg-gray-100 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                        URL
                      </th>
                      <th className="py-2 px-4 border-b border-gray-200 bg-gray-100 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                        Parameter
                      </th>
                      <th className="py-2 px-4 border-b border-gray-200 bg-gray-100 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider">
                        Payload
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.vulnerabilities.map((vuln, index) => (
                      <tr key={index} className={index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}>
                        <td className="py-2 px-4 border-b border-gray-200 text-sm">
                          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${vuln.type.includes('XSS') ? 'bg-red-100 text-red-800' : 'bg-orange-100 text-orange-800'}`}>
                            {vuln.type}
                          </span>
                        </td>
                        <td className="py-2 px-4 border-b border-gray-200 text-sm">
                          <a href={vuln.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:text-blue-800 flex items-center">
                            {vuln.url.length > 30 ? vuln.url.substring(0, 30) + '...' : vuln.url}
                            <ExternalLink className="w-3 h-3 ml-1" />
                          </a>
                        </td>
                        <td className="py-2 px-4 border-b border-gray-200 text-sm">
                          {vuln.param}
                        </td>
                        <td className="py-2 px-4 border-b border-gray-200 text-sm font-mono">
                          {vuln.payload.length > 20 ? vuln.payload.substring(0, 20) + '...' : vuln.payload}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-sm text-green-600">No vulnerabilities detected</div>
            )}
          </div>
        )}
        
        <div className="flex justify-between">
          <button
            onClick={() => setActiveTab('dashboard')}
            className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
          >
            Back to Scanner
          </button>
          
          {scanResults.report_file && (
            <a
              href={`/reports/${scanResults.report_file}`}
              target="_blank"
              rel="noopener noreferrer"
              className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline flex items-center"
            >
              <FileText className="w-4 h-4 mr-2" />
              View Full Report
            </a>
          )}
        </div>
      </div>
    );
  };

  const renderDocumentation = () => (
    <div className="p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">Documentation</h2>
      
      <div className="prose max-w-none">
        <h3>BlackWidow - Ethical Web Security Scanner</h3>
        <p>
          BlackWidow is an ethical web security scanning tool written in Python. It helps security professionals 
          and developers identify potential vulnerabilities in web applications through automated testing and analysis.
        </p>
        
        <h4>Features</h4>
        <ul>
          <li><strong>SSL/TLS Configuration Analysis</strong> - Certificate validation, protocol verification, security headers check</li>
          <li><strong>Port Scanning</strong> - Common ports detection, service identification, basic vulnerability assessment</li>
          <li><strong>Web Vulnerability Detection</strong> - XSS tests, SQL Injection detection, common sensitive paths discovery</li>
          <li><strong>Web Crawler</strong> - Recursive site mapping, form detection, dynamic URL discovery</li>
          <li><strong>Reporting</strong> - Detailed HTML reports, comprehensive logging, vulnerability assessment summary</li>
        </ul>
        
        <h4>Command Line Usage</h4>
        <pre className="bg-gray-800 text-green-400 p-3 rounded font-mono text-sm overflow-x-auto">
          python blackwidow.py https://target-website.com --threads 5 --timeout 10 --depth 2
        </pre>
        
        <h4>API Usage</h4>
        <p>BlackWidow provides a REST API for integration with other tools:</p>
        <pre className="bg-gray-800 text-green-400 p-3 rounded font-mono text-sm overflow-x-auto">
{`# Start a scan
curl -X POST http://localhost:5000/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"target": "https://example.com", "threads": 5, "timeout": 10, "depth": 2}'

# List available reports
curl http://localhost:5000/api/reports`}
        </pre>
        
        <h4>Legal Disclaimer</h4>
        <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-4">
          <p className="text-yellow-700">
            BlackWidow should only be used for authorized security testing.
            Users must ensure they have explicit permission to test the target systems.
            The developers assume no liability for misuse or damage caused by this tool.
          </p>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-100">
      <header className="bg-red-800 text-white shadow-md">
        <div className="container mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center">
              <Shield className="w-8 h-8 mr-2" />
              <h1 className="text-2xl font-bold">BlackWidow</h1>
            </div>
            <div className="text-sm">v1.0.0</div>
          </div>
        </div>
      </header>
      
      <main className="container mx-auto px-4 py-8">
        <div className="mb-6">
          <div className="flex border-b border-gray-200">
            <button
              className={`py-2 px-4 font-medium text-sm focus:outline-none ${
                activeTab === 'dashboard' ? 'border-b-2 border-red-500 text-red-600' : 'text-gray-500 hover:text-gray-700'
              }`}
              onClick={() => setActiveTab('dashboard')}
            >
              Scanner
            </button>
            <button
              className={`py-2 px-4 font-medium text-sm focus:outline-none ${
                activeTab === 'results' ? 'border-b-2 border-red-500 text-red-600' : 'text-gray-500 hover:text-gray-700'
              }`}
              onClick={() => setActiveTab('results')}
              disabled={!scanResults}
            >
              Results
            </button>
            <button
              className={`py-2 px-4 font-medium text-sm focus:outline-none ${
                activeTab === 'documentation' ? 'border-b-2 border-red-500 text-red-600' : 'text-gray-500 hover:text-gray-700'
              }`}
              onClick={() => setActiveTab('documentation')}
            >
              Documentation
            </button>
          </div>
        </div>
        
        {activeTab === 'dashboard' && renderDashboard()}
        {activeTab === 'results' && renderResults()}
        {activeTab === 'documentation' && renderDocumentation()}
      </main>
      
      <footer className="bg-gray-800 text-white py-4">
        <div className="container mx-auto px-4 text-center text-sm">
          <p>© 2025 Malic1tus | MIT License | Use responsibly</p>
        </div>
      </footer>
    </div>
  );
}

export default App;