function App() {
  return (
    <div
      style={{
        display: "flex",
        background: "#0d1117",
        color: "white",
        minHeight: "100vh",
        fontFamily: "Arial"
      }}
    >
      {/* Sidebar */}

      <div
        style={{
          width: "260px",
          background: "#161b22",
          padding: "20px",
          borderRight: "1px solid #30363d"
        }}
      >
        <h2>LabThinkTank</h2>

        <hr />

        <p>🏴 Recon Automation</p>
        <p>🧠 Threat Intelligence</p>
        <p>🛰️ OSINT</p>
        <p>⚔️ Offensive Labs</p>
        <p>🎯 MITRE ATT&CK</p>
        <p>📊 Reporting</p>
      </div>

      {/* Main */}

      <div style={{ flex: 1, padding: "30px" }}>
        <h1>Cybersecurity Offensive Platform</h1>

        <p>
          Offensive Operations • Recon • Threat Intelligence • Labs
        </p>

        <hr />

        {/* Metrics */}

        <div
          style={{
            display: "flex",
            gap: "20px",
            marginTop: "30px"
          }}
        >
          <div
            style={{
              background: "#161b22",
              padding: "20px",
              borderRadius: "10px",
              width: "220px"
            }}
          >
            <h3>Targets</h3>
            <h1>24</h1>
          </div>

          <div
            style={{
              background: "#161b22",
              padding: "20px",
              borderRadius: "10px",
              width: "220px"
            }}
          >
            <h3>Findings</h3>
            <h1>138</h1>
          </div>

          <div
            style={{
              background: "#161b22",
              padding: "20px",
              borderRadius: "10px",
              width: "220px"
            }}
          >
            <h3>Nuclei Alerts</h3>
            <h1>17</h1>
          </div>
        </div>

        {/* Findings */}

        <div
          style={{
            marginTop: "40px",
            background: "#161b22",
            padding: "20px",
            borderRadius: "10px"
          }}
        >
          <h2>Recent Findings</h2>

          <hr />

          <p>[HIGH] Exposed Login Panel</p>
          <p>[MEDIUM] Missing Security Headers</p>
          <p>[LOW] Directory Listing Enabled</p>
        </div>
      </div>
    </div>
  )
}

export default App
