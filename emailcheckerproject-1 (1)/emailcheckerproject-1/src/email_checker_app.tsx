import React, { useState, useRef } from 'react';
import { Play, Square, Download, Upload, Trash2, Settings, Database } from 'lucide-react';

const EmailChecker = () => {
  const [currentPage, setCurrentPage] = useState('main');
  const [isRunning, setIsRunning] = useState(false);
  
  // API Configuration
  const [apiKey, setApiKey] = useState('');
  const [httpRequest, setHttpRequest] = useState('');
  const [httpMethod, setHttpMethod] = useState('GET');
  const [requestBody, setRequestBody] = useState('');
  const [responseTerminal, setResponseTerminal] = useState('');
  
  // Email/Password Configuration
  const [emailPassList, setEmailPassList] = useState('');
  const [threadCount, setThreadCount] = useState(10);
  const [useEmailPass, setUseEmailPass] = useState(true);
  
  // Proxy Configuration
  const [proxyList, setProxyList] = useState('');
  const [useProxy, setUseProxy] = useState(false);
  const [proxyTypes, setProxyTypes] = useState({
    socks5: true,
    http: false,
    https: false,
    socks4: false
  });
  
  // Email Protocol Configuration
  const [protocols, setProtocols] = useState({
    pop3: true,
    imap: true,
    smtp: false
  });
  
  // Email Provider Configuration
  const [providers, setProviders] = useState({
    gmail: true,
    hotmail: true,
    outlook: true,
    yahoo: false,
    accountimail: true,
    aol: false,
    icloud: false
  });
  
  // Statistics
  const [stats, setStats] = useState({
    loaded: 0,
    checked: 0,
    remaining: 0,
    good: 0,
    bad: 0,
    invalid: 0
  });
  
  // Results storage
  const [results, setResults] = useState([]);
  const [databases, setDatabases] = useState([]);
  
  // File handling
  const emailFileRef = useRef(null);
  const proxyFileRef = useRef(null);
  
  const loadEmailFile = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target.result;
        setEmailPassList(content);
        const lines = content.split('\n').filter(line => line.trim());
        setStats(prev => ({ ...prev, loaded: lines.length, remaining: lines.length }));
      };
      reader.readAsText(file);
    }
  };
  
  const loadProxyFile = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setProxyList(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  const makeRealAPICall = async (email, password, proxy = null) => {
    try {
      const requestOptions = {
        method: httpMethod,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        }
      };

      if (httpMethod === 'POST' && requestBody) {
        requestOptions.body = requestBody.replace('{{email}}', email).replace('{{password}}', password);
      }

      let url = httpRequest.replace('{{email}}', email).replace('{{password}}', password);
      
      const response = await fetch(url, requestOptions);
      const data = await response.json();
      
      setResponseTerminal(prev => prev + `Response for ${email}: ${JSON.stringify(data)}\n`);
      return { success: response.ok, data, email, password };
    } catch (error) {
      setResponseTerminal(prev => prev + `Error checking ${email}: ${error.message}\n`);
      return { success: false, error: error.message, email, password };
    }
  };

  const checkEmailProtocol = async (email, password, protocol) => {
    const [, domain] = email.split('@');
    
    const protocolPorts = {
      pop3: 995,
      imap: 993,
      smtp: 587
    };

    try {
      // Real protocol check would require server-side implementation
      // This is where actual POP3/IMAP/SMTP connections would be made
      const result = await fetch('/api/check-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          protocol,
          port: protocolPorts[protocol],
          domain
        })
      });
      
      return await result.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const startChecking = async () => {
    if (!apiKey || !httpRequest) {
      setResponseTerminal('Error: API Key and HTTP Request URL are required\n');
      return;
    }

    setIsRunning(true);
    setResponseTerminal('Starting real email verification...\n');
    
    const emailLines = emailPassList.split('\n').filter(line => line.trim());
    const proxies = proxyList.split('\n').filter(line => line.trim());
    
    for (let i = 0; i < emailLines.length && isRunning; i++) {
      const line = emailLines[i];
      const [email, password] = line.split(':');
      
      if (!email || !password) {
        setStats(prev => ({ ...prev, invalid: prev.invalid + 1 }));
        continue;
      }

      const proxy = useProxy && proxies.length > 0 ? proxies[i % proxies.length] : null;
      
      // Real API call
      const result = await makeRealAPICall(email, password, proxy);
      
      if (result.success) {
        setStats(prev => ({ ...prev, good: prev.good + 1 }));
        setResults(prev => [...prev, { 
          email, 
          password, 
          status: 'VALID', 
          timestamp: new Date().toISOString(),
          response: result.data
        }]);
      } else {
        setStats(prev => ({ ...prev, bad: prev.bad + 1 }));
        setResults(prev => [...prev, { 
          email, 
          password, 
          status: 'INVALID', 
          timestamp: new Date().toISOString(),
          error: result.error
        }]);
      }
      
      setStats(prev => ({ 
        ...prev, 
        checked: prev.checked + 1,
        remaining: emailLines.length - (prev.checked + 1)
      }));
    }
    
    setIsRunning(false);
    setResponseTerminal(prev => prev + 'Checking completed.\n');
  };

  const stopChecking = () => {
    setIsRunning(false);
    setResponseTerminal(prev => prev + 'Checking stopped by user.\n');
  };

  const downloadResults = () => {
    const validResults = results.filter(r => r.status === 'VALID');
    const dataStr = validResults.map(r => `${r.email}:${r.password}`).join('\n');
    const dataBlob = new Blob([dataStr], { type: 'text/plain' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'valid_emails.txt';
    link.click();
    URL.revokeObjectURL(url);
  };

  const renderMainPage = () => (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold mb-6">Email Checker - Main Operations</h2>
      
      <div className="grid grid-cols-2 gap-4">
        <button 
          onClick={() => setCurrentPage('api')}
          className="p-4 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          API Configuration
        </button>
        
        <button 
          onClick={() => setCurrentPage('email')}
          className="p-4 bg-green-600 text-white rounded hover:bg-green-700"
        >
          Email/Password Settings
        </button>
        
        <button 
          onClick={() => setCurrentPage('proxy')}
          className="p-4 bg-purple-600 text-white rounded hover:bg-purple-700"
        >
          Proxy Configuration
        </button>
        
        <button 
          onClick={() => setCurrentPage('protocols')}
          className="p-4 bg-orange-600 text-white rounded hover:bg-orange-700"
        >
          Email Protocols
        </button>
        
        <button 
          onClick={() => setCurrentPage('providers')}
          className="p-4 bg-red-600 text-white rounded hover:bg-red-700"
        >
          Email Providers
        </button>
        
        <button 
          onClick={() => setCurrentPage('database')}
          className="p-4 bg-gray-600 text-white rounded hover:bg-gray-700"
        >
          Database Management
        </button>
      </div>
      
      <div className="bg-gray-100 p-4 rounded">
        <h3 className="font-bold mb-2">Statistics</h3>
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div>Loaded: {stats.loaded}</div>
          <div>Checked: {stats.checked}</div>
          <div>Remaining: {stats.remaining}</div>
          <div className="text-green-600">Good: {stats.good}</div>
          <div className="text-red-600">Bad: {stats.bad}</div>
          <div className="text-yellow-600">Invalid: {stats.invalid}</div>
        </div>
      </div>
      
      <div className="flex space-x-2">
        <button 
          onClick={startChecking}
          disabled={isRunning}
          className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded disabled:bg-gray-400"
        >
          <Play size={16} />
          <span>Start</span>
        </button>
        
        <button 
          onClick={stopChecking}
          disabled={!isRunning}
          className="flex items-center space-x-2 px-4 py-2 bg-red-600 text-white rounded disabled:bg-gray-400"
        >
          <Square size={16} />
          <span>Stop</span>
        </button>
        
        <button 
          onClick={downloadResults}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded"
        >
          <Download size={16} />
          <span>Download</span>
        </button>
      </div>
    </div>
  );

  const renderAPIPage = () => (
    <div className="space-y-4">
      <button 
        onClick={() => setCurrentPage('main')}
        className="mb-4 px-4 py-2 bg-gray-500 text-white rounded"
      >
        ← Back to Main
      </button>
      
      <h2 className="text-2xl font-bold mb-6">API Configuration</h2>
      
      <div>
        <label className="block font-bold mb-2">API Key:</label>
        <input
          type="text"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          className="w-full p-2 border rounded"
          placeholder="Enter your API key"
        />
      </div>
      
      <div>
        <label className="block font-bold mb-2">HTTPS Request URL:</label>
        <input
          type="text"
          value={httpRequest}
          onChange={(e) => setHttpRequest(e.target.value)}
          className="w-full p-2 border rounded"
          placeholder="https://api.example.com/verify?email={{email}}&password={{password}}"
        />
      </div>
      
      <div>
        <label className="block font-bold mb-2">HTTP Method:</label>
        <select
          value={httpMethod}
          onChange={(e) => setHttpMethod(e.target.value)}
          className="w-full p-2 border rounded"
        >
          <option value="GET">GET</option>
          <option value="POST">POST</option>
        </select>
      </div>
      
      <div>
        <label className="block font-bold mb-2">Request Body (for POST):</label>
        <textarea
          value={requestBody}
          onChange={(e) => setRequestBody(e.target.value)}
          className="w-full p-2 border rounded h-24"
          placeholder='{"email": "{{email}}", "password": "{{password}}"}'
        />
      </div>
      
      <div>
        <label className="block font-bold mb-2">Response Terminal:</label>
        <textarea
          value={responseTerminal}
          readOnly
          className="w-full p-2 border rounded h-48 bg-black text-green-400 font-mono text-sm"
        />
      </div>
    </div>
  );

  const renderEmailPage = () => (
    <div className="space-y-4">
      <button 
        onClick={() => setCurrentPage('main')}
        className="mb-4 px-4 py-2 bg-gray-500 text-white rounded"
      >
        ← Back to Main
      </button>
      
      <h2 className="text-2xl font-bold mb-6">Email/Password Configuration</h2>
      
      <div>
        <label className="block font-bold mb-2">Email:Password List:</label>
        <textarea
          value={emailPassList}
          onChange={(e) => setEmailPassList(e.target.value)}
          className="w-full p-2 border rounded h-32"
          placeholder="email1@domain.com:password1&#10;email2@domain.com:password2"
        />
      </div>
      
      <div className="flex items-center space-x-4">
        <input
          type="file"
          ref={emailFileRef}
          onChange={loadEmailFile}
          accept=".txt"
          className="hidden"
        />
        <button
          onClick={() => emailFileRef.current.click()}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded"
        >
          <Upload size={16} />
          <span>Load File</span>
        </button>
        
        <label className="flex items-center space-x-2">
          <input
            type="checkbox"
            checked={useEmailPass}
            onChange={(e) => setUseEmailPass(e.target.checked)}
          />
          <span>Use Email:Password for checking</span>
        </label>
      </div>
      
      <div>
        <label className="block font-bold mb-2">Thread Count:</label>
        <input
          type="number"
          value={threadCount}
          onChange={(e) => setThreadCount(parseInt(e.target.value))}
          className="w-full p-2 border rounded"
          min="1"
          max="100"
        />
      </div>
    </div>
  );

  const renderProxyPage = () => (
    <div className="space-y-4">
      <button 
        onClick={() => setCurrentPage('main')}
        className="mb-4 px-4 py-2 bg-gray-500 text-white rounded"
      >
        ← Back to Main
      </button>
      
      <h2 className="text-2xl font-bold mb-6">Proxy Configuration</h2>
      
      <div>
        <label className="flex items-center space-x-2 mb-4">
          <input
            type="checkbox"
            checked={useProxy}
            onChange={(e) => setUseProxy(e.target.checked)}
          />
          <span className="font-bold">Use Proxy</span>
        </label>
      </div>
      
      <div>
        <label className="block font-bold mb-2">Proxy List:</label>
        <textarea
          value={proxyList}
          onChange={(e) => setProxyList(e.target.value)}
          className="w-full p-2 border rounded h-32"
          placeholder="proxy1:port:user:pass&#10;proxy2:port:user:pass"
        />
      </div>
      
      <div className="flex items-center space-x-4">
        <input
          type="file"
          ref={proxyFileRef}
          onChange={loadProxyFile}
          accept=".txt"
          className="hidden"
        />
        <button
          onClick={() => proxyFileRef.current.click()}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded"
        >
          <Upload size={16} />
          <span>Load</span>
        </button>
        
        <button className="px-4 py-2 bg-green-600 text-white rounded">Check</button>
        <button className="px-4 py-2 bg-red-600 text-white rounded">Delete</button>
        <button className="px-4 py-2 bg-yellow-600 text-white rounded">Paste</button>
      </div>
      
      <div>
        <label className="block font-bold mb-2">Proxy Types:</label>
        <div className="space-y-2">
          {Object.keys(proxyTypes).map(type => (
            <label key={type} className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={proxyTypes[type]}
                onChange={(e) => setProxyTypes(prev => ({ ...prev, [type]: e.target.checked }))}
              />
              <span className="uppercase">{type}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );

  const renderProtocolsPage = () => (
    <div className="space-y-4">
      <button 
        onClick={() => setCurrentPage('main')}
        className="mb-4 px-4 py-2 bg-gray-500 text-white rounded"
      >
        ← Back to Main
      </button>
      
      <h2 className="text-2xl font-bold mb-6">Email Protocols</h2>
      
      <div className="space-y-4">
        {Object.keys(protocols).map(protocol => (
          <label key={protocol} className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={protocols[protocol]}
              onChange={(e) => setProtocols(prev => ({ ...prev, [protocol]: e.target.checked }))}
            />
            <span className="uppercase font-bold">{protocol}</span>
          </label>
        ))}
      </div>
    </div>
  );

  const renderProvidersPage = () => (
    <div className="space-y-4">
      <button 
        onClick={() => setCurrentPage('main')}
        className="mb-4 px-4 py-2 bg-gray-500 text-white rounded"
      >
        ← Back to Main
      </button>
      
      <h2 className="text-2xl font-bold mb-6">Email Providers</h2>
      
      <div className="space-y-4">
        {Object.keys(providers).map(provider => (
          <label key={provider} className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={providers[provider]}
              onChange={(e) => setProviders(prev => ({ ...prev, [provider]: e.target.checked }))}
            />
            <span className="font-bold capitalize">{provider}</span>
          </label>
        ))}
      </div>
    </div>
  );

  const renderDatabasePage = () => (
    <div className="space-y-4">
      <button 
        onClick={() => setCurrentPage('main')}
        className="mb-4 px-4 py-2 bg-gray-500 text-white rounded"
      >
        ← Back to Main
      </button>
      
      <h2 className="text-2xl font-bold mb-6">Database Management</h2>
      
      <div className="bg-white border rounded p-4">
        <h3 className="font-bold mb-4">Results Database</h3>
        <div className="max-h-96 overflow-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b">
                <th className="text-left p-2">Email</th>
                <th className="text-left p-2">Status</th>
                <th className="text-left p-2">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {results.map((result, index) => (
                <tr key={index} className="border-b">
                  <td className="p-2">{result.email}</td>
                  <td className={`p-2 ${result.status === 'VALID' ? 'text-green-600' : 'text-red-600'}`}>
                    {result.status}
                  </td>
                  <td className="p-2">{new Date(result.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50 p-4">
      <div className="max-w-6xl mx-auto">
        <h1 className="text-3xl font-bold text-center mb-8">Email Checker Application</h1>
        
        {currentPage === 'main' && renderMainPage()}
        {currentPage === 'api' && renderAPIPage()}
        {currentPage === 'email' && renderEmailPage()}
        {currentPage === 'proxy' && renderProxyPage()}
        {currentPage === 'protocols' && renderProtocolsPage()}
        {currentPage === 'providers' && renderProvidersPage()}
        {currentPage === 'database' && renderDatabasePage()}
      </div>
    </div>
  );
};

export default EmailChecker;