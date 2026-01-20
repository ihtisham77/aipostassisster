# 🤖 Intelligent MCP Post-Exploitation Assistant

> **Context-Aware Operator Copilot for Safe, Stealthy Post-Exploitation**

## Overview

This framework is an **intelligent MCP-based post-exploitation assistant** that acts as your operator copilot, not a noisy auto-exploit tool. It provides decision support, risk analysis, and actionable recommendations without "burning the host."

### Core Philosophy

**ASSIST, DON'T AUTO-EXPLOIT**
- Aggregate signals and assess feasibility
- Recommend actions with risk/reward analysis
- Validate results and track OPSEC state
- Maintain stealth and operational security

---

## 🎯 Key Features

### 1. **Risk & Noise Scoring**
Every finding is automatically scored for:
- **Impact Score** (0-100): How valuable is this finding?
- **Noise Score** (0-100): How likely to trigger detection?
- **Feasibility Score** (0-100): How likely to succeed?
- **Stealth Score** (0-100): How covert is this action?

### 2. **OPSEC Assessment**
Automatically detects security controls and provides context:
- EDR/AV detection
- SIEM/logging detection
- Privilege level awareness
- Domain membership detection
- Threat level assessment (Low → Critical)

### 3. **Attack Path Generation**
Builds actionable attack chains:
- Multi-phase attack sequences
- Risk-ranked pathways
- Step-by-step execution plans
- Detection likelihood per path

### 4. **Quick Wins**
Identifies low-hanging fruit:
- High impact + Low noise + High feasibility
- Immediate opportunities
- Safe initial footholds

### 5. **Recommended Actions**
AI-prioritized next steps:
- Risk/reward optimized
- Context-aware suggestions
- OPSEC-safe techniques
- Phase-appropriate actions

---

## 🔄 Post-Exploitation Phases

The framework assists across 7 phases matching standard attack lifecycle:

### Phase 1: Reconnaissance
**Goal**: Build accurate picture of compromised host

**Assistant Capabilities:**
- System profiling (OS, kernel, patches)
- User & group enumeration
- Network context (interfaces, routes, DNS)
- Trust relationships
- Security control detection (EDR, AV, SIEM)

**Example Output:**
```
[OPSEC] EDR Detected: CrowdStrike Falcon
[RECOMMENDATION] Avoid memory manipulation and process injection
[RECOMMENDATION] Use living-off-the-land techniques
```

### Phase 2: Credential Access
**Goal**: Identify feasible credential access paths

**Assistant Capabilities:**
- Credential source detection
- Privilege-aware feasibility checks
- Noise/risk assessment per technique
- Safe vs risky method identification

**Example Output:**
```
[QUICK WIN] Browser credentials accessible
  Impact: 75% | Noise: 20% | Feasibility: 90%
  → SAFE: Low-noise credential harvesting method

[CAUTION] LSASS memory accessible
  Impact: 95% | Noise: 85% | Feasibility: 80%
  → AVOID: LSASS access with EDR will trigger alerts
```

### Phase 3: Privilege Escalation
**Goal**: Identify realistic, low-risk escalation paths

**Assistant Capabilities:**
- Vector discovery and ranking
- Misconfiguration analysis
- Compatibility checking (OS/kernel)
- Detection likelihood assessment

**Example Output:**
```
[RECOMMENDED] Writable service binary found
  → PREFERRED: Configuration-based escalation is stealthier
  → Noise: 35% | Feasibility: 85%

[HIGH RISK] Kernel exploit available
  → Kernel exploits are noisy and may crash system
  → Use only as last resort
```

### Phase 4: Persistence
**Goal**: Maintain access with minimal detection risk

**Assistant Capabilities:**
- Persistence method enumeration
- Detection surface estimation
- Survivability vs stealth analysis
- Cleanup planning

**Example Output:**
```
[RECOMMENDED] User-level registry persistence
  → VIABLE: Relatively stealthy persistence option
  → Noise: 45% | Stealth: 55%

[AVOID] System service persistence
  → NOISY: This persistence method likely monitored
  → Alternative: User-level methods recommended
```

### Phase 5: Lateral Movement
**Goal**: Move only when strategically advantageous

**Assistant Capabilities:**
- Credential-to-target mapping
- Trust path discovery
- Protocol availability assessment
- Network segmentation awareness

**Example Output:**
```
[RECOMMENDED] SMB lateral movement to FILE-SERVER
  → READY: Target accessible with current credentials
  → 3 hosts accessible | 1 is domain controller
  → Protocol: SMB allowed | WinRM blocked
```

### Phase 6: Exfiltration
**Goal**: Exfiltrate necessary data via allowed channels

**Assistant Capabilities:**
- Egress channel assessment
- Data sensitivity tagging
- Volume-based risk estimation
- Encoding recommendations

**Example Output:**
```
[RECOMMENDED] HTTPS exfiltration channel
  → STEALTHY: HTTPS blends with normal traffic
  → Egress allowed and not inspected

[ALTERNATIVE] DNS tunneling
  → COVERT: DNS tunneling is stealthy but slow
  → Use for small volumes or when HTTPS unavailable
```

### Phase 7: Cleanup
**Goal**: Leave minimal artifacts

**Assistant Capabilities:**
- Artifact tracking
- Log touch detection
- Persistence rollback
- Verification of removal

**Example Output:**
```
[ARTIFACTS] 3 items require cleanup:
  1. Service entry: BackupService
  2. Scheduled task: SystemUpdate
  3. Temp binary: C:\Users\...\temp.exe

[CAUTION] Do not clear Windows Security logs
  → This increases detection likelihood
```

---

## 📊 Report Intelligence

Reports now include intelligent analysis sections:

### Console Report Sections
1. **Executive Summary** - Risk scoring and statistics
2. **OPSEC Assessment** - Threat level and environment context
3. **Quick Wins** - Low-hanging fruit opportunities
4. **Recommended Actions** - Prioritized next steps
5. **Attack Paths** - Multi-phase attack chains
6. **Module Findings** - Traditional detailed findings

### Example Report Output

```
█ OPSEC ASSESSMENT

  Threat Level: High

  Environment:
    EDR Detected:       ✓ Yes (CrowdStrike)
    SIEM Detected:      ✓ Yes
    Privilege Level:    User
    Domain Joined:      ✓ Yes

  Key Recommendations:
    1. EDR detected: Avoid memory manipulation and process injection
    2. Use living-off-the-land techniques and legitimate tools
    3. Running as unprivileged user: Focus on user-level techniques first

█ QUICK WINS (Low-Hanging Fruit)

  High impact, low detection risk, high feasibility

  1. [CREDENTIAL_ACCESS] Browser credentials accessible
     Impact: 75% │ Noise: 20% │ Feasibility: 90%
     → SAFE: Low-noise credential harvesting method

  2. [LATERAL_MOVEMENT] SMB access to file server
     Impact: 80% │ Noise: 30% │ Feasibility: 95%
     → READY: Target accessible with current credentials

█ RECOMMENDED NEXT ACTIONS

  Prioritized actions based on risk/reward analysis

  1. [CREDENTIAL_ACCESS]
     Harvest browser stored credentials
     Priority: 85 │ Impact: 75 │ Stealth: 80
     → SAFE: Low-noise credential harvesting method

  2. [LATERAL_MOVEMENT]
     Access file server via SMB
     Priority: 82 │ Impact: 80 │ Stealth: 70
     → READY: Target accessible with current credentials

█ ATTACK PATHS

  Generated attack chains from reconnaissance to objectives

  Path 1: reconnaissance → credential_access → lateral_movement
  Risk: Low Risk │ Score: 78.5/100 │ Steps: 3
  → RECOMMENDED: High-value path with good feasibility and stealth

    1. [RECONNAISSANCE] Domain-joined Windows workstation
    2. [CREDENTIAL_ACCESS] Saved domain credentials found
    3. [LATERAL_MOVEMENT] SMB access to file server
```

---

## 🚀 Usage

### Basic Workflow

1. **Generate and Deploy Agent**
```bash
python3 operator/agent_generator.py linux
# Deploy agent to target system
```

2. **Run Assessment (All Phases)**
```bash
python3 operator/cli.py
> module <agent_id> all
```

3. **View Intelligent Report**
```bash
> results <agent_id>
```

The report automatically includes:
- OPSEC assessment
- Quick wins
- Recommended actions
- Attack paths

### Generate Full Reports

```bash
# JSON with intelligence data
> report <agent_id> json

# HTML with visualizations
> report <agent_id> html

# All formats
> report <agent_id> all
```

---

## 🧠 Intelligence Under the Hood

### Risk Scoring Algorithm

Each finding is scored across 4 dimensions:

```python
Impact Score (40% weight)
  - Based on severity level
  - Critical: 100, High: 80, Medium: 50, Low: 30, Info: 10

Feasibility Score (35% weight)
  - Privilege requirements met?
  - Compatible with current OS/kernel?
  - Security controls present?
  - Confidence level of finding?

Stealth Score (25% weight)
  - Inverse of noise score
  - Considers: EDR, SIEM, technique type
  - Kernel ops: +30 noise
  - Memory access: +25 noise
  - File ops: +10 noise
  - Enumeration: -10 noise

Composite Score = 0.4×Impact + 0.35×Feasibility + 0.25×Stealth
```

### Attack Path Generation

```
1. Build attack graph from findings
   - Nodes = findings
   - Edges = phase dependencies + semantic relationships

2. Find paths from reconnaissance to objectives
   - Max depth: 6 phases
   - Minimum viable: 3 steps

3. Rank paths by composite score
   - High-value paths surface first
   - Risk-aware prioritization

4. Generate step-by-step execution plans
```

---

## 🎓 Best Practices

### 1. **Trust the OPSEC Assessment**
If threat level is "High" or "Critical":
- Prioritize stealth over speed
- Avoid noisy techniques
- Use living-off-the-land methods

### 2. **Start with Quick Wins**
Low-hanging fruit provides:
- Safe initial foothold
- Credentials for next phase
- Low detection risk

### 3. **Follow Recommended Actions**
AI-ranked by risk/reward:
- Considers environment context
- Phase-appropriate suggestions
- OPSEC-safe by default

### 4. **Use Attack Paths for Planning**
- Understand full attack chain before acting
- Identify roadblocks early
- Plan cleanup from the start

### 5. **Monitor Detection Likelihood**
Each finding shows:
- Noise score
- Detection likelihood
- OPSEC-safe flag

---

## 🔧 Configuration

### Enable/Disable Intelligence

Intelligence is enabled by default. To disable:

```python
# In report_generator.py
generator = ReportGenerator(agent_data, results, enable_intelligence=False)
```

### Adjust Risk Thresholds

Edit `operator/risk_scorer.py`:

```python
# Noise scoring thresholds
base_noise = module_noise.get(module, 30)

# EDR penalty
if self.environment_context['has_edr']:
    base_noise += 25  # Adjust this value
```

### Customize Recommendations

Edit `operator/risk_scorer.py`:

```python
def _generate_recommendation(self, finding, module, impact, noise, feasibility):
    # Add custom logic here
    if impact >= 70 and noise <= 40:
        return "RECOMMENDED: High impact, low detection risk"
```

---

## 📈 Example Scenarios

### Scenario 1: Domain Workstation with EDR

**Environment:**
- Windows 10 workstation
- CrowdStrike Falcon EDR
- Domain-joined
- User-level access

**Intelligence Output:**
```
Threat Level: High
OPSEC: Avoid memory manipulation, use LOLbins

Quick Wins:
- Browser credential harvesting (Noise: 20%)
- Saved Wi-Fi passwords (Noise: 15%)

Avoid:
- LSASS memory dump (Noise: 90%)
- Process injection (Noise: 80%)

Recommended Path:
1. Harvest browser credentials
2. Find domain credentials
3. Lateral movement via SMB
```

### Scenario 2: Linux Server - Low Security

**Environment:**
- Ubuntu 20.04
- No EDR detected
- Sudo misconfiguration found
- Standard user access

**Intelligence Output:**
```
Threat Level: Low
OPSEC: More aggressive techniques viable

Quick Wins:
- Sudo privilege escalation (Noise: 25%, Impact: 95%)
- Readable /etc/shadow backup (Noise: 30%)

Recommended Path:
1. Exploit sudo misconfiguration → root
2. Dump /etc/shadow
3. Install rootkit persistence
4. Enumerate network
5. Pivot to other systems
```

---

## 🔬 Technical Details

### File Structure

```
operator/
├── risk_scorer.py           # Risk scoring and OPSEC analysis
├── attack_path_generator.py # Attack path generation
├── report_generator.py      # Enhanced with intelligence
└── ...

Key Classes:
- RiskScorer: Analyzes environment and scores findings
- AttackPathGenerator: Builds attack graphs and generates paths
- ReportGenerator: Integrates intelligence into reports
```

### Integration Points

1. **Report Generation** (`report_generator.py`)
   - Automatically initializes intelligence
   - Scores all findings
   - Generates attack paths
   - Adds intelligence sections to reports

2. **MCP Server** (`mcp_server.py`)
   - Exposes intelligence via MCP tools
   - Allows LLMs to leverage analysis
   - Natural language queries

3. **CLI** (`cli.py`)
   - Results command shows intelligence
   - Report command includes all features

---

## 🎯 Success Metrics

A successful post-exploitation engagement using this assistant:

✅ **Zero detections** from intelligent technique selection
✅ **Efficient** - No wasted time on infeasible paths
✅ **Complete** - All objectives achieved systematically
✅ **Documented** - Clear attack paths for reporting
✅ **Clean** - Minimal artifacts left behind

---

## 🤝 Contributing

Enhancement ideas:
- Machine learning for risk prediction
- Historical success rate tracking
- Custom playbook integration
- Real-time detection monitoring
- Automated OPSEC violation warnings

---

## ⚖️ Legal & Ethical Use

**AUTHORIZED USE ONLY**

This framework is designed for:
- ✅ Authorized penetration testing
- ✅ Red team engagements
- ✅ Security research
- ✅ CTF competitions
- ✅ Educational purposes

**NOT for:**
- ❌ Unauthorized access
- ❌ Malicious activity
- ❌ Real-world attacks without permission

Always obtain explicit written authorization before deployment.

---

## 📚 Additional Resources

- [Attack Lifecycle](https://attack.mitre.org/)
- [OPSEC Best Practices](docs/opsec.md)
- [Risk Scoring Details](operator/risk_scorer.py)
- [Attack Path Algorithm](operator/attack_path_generator.py)

---

**Built for operators, by operators.** 🎯

Make informed decisions. Stay stealthy. Complete objectives.
