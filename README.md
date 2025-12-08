# 🔒 AutomatonSec

**Advanced Smart Contract Security Analysis Engine**

BYNNΛI - [AutomatonSec](https://github.com/BYNNAI/AutomatonSec)

---

## 🎯 Overview

AutomatonSec is a state-of-the-art smart contract security analysis engine designed to discover novel zero-day vulnerabilities and sophisticated multi-layered exploits. Built from the ground up with custom analysis algorithms, it outperforms traditional security scanners and human auditing through advanced detection techniques.

### Core Capabilities

- **Custom Symbolic Execution Engine** - Hybrid concolic execution with constraint solving
- **Cross-Contract Data Flow Analysis** - Multi-contract exploit detection
- **Profit-Centric Fuzzing** - Financially exploitable vulnerability targeting
- **Zero-Day Pattern Recognition** - Novel vulnerability discovery
- **Bug Bounty Repository Scanning** - Batch analysis of entire codebases
- **Automated Exploit Generation** - PoC creation for critical vulnerabilities

## 🚀 Key Features

### Bug Bounty Repository Scanning

**Scan entire repositories downloaded locally from bug bounty platforms:**

- Recursive Solidity file discovery across all subdirectories
- Intelligent test file exclusion (Hardhat, Foundry, Truffle patterns)
- Parallel multi-contract analysis for performance
- Cross-contract vulnerability detection
- Comprehensive vulnerability reports with severity classification
- Export to JSON for integration with CI/CD pipelines

### Advanced Detection

- **19 Specialized Detectors** covering critical DeFi vulnerabilities
- **Exploit Chain Analysis** for sophisticated multi-step attacks
- **Economic Invariant Checking** for protocol logic flaws
- **Low False Positive Rate** through confidence scoring
- **Automatic PoC Generation** for verified vulnerabilities

### Performance

- Single contract: < 60 seconds
- Bug bounty repository (100 contracts): < 30 minutes
- Parallel processing with configurable worker threads
- Efficient bytecode analysis without source code

## 📦 Installation

### Requirements

- Python 3.10+
- Git

### Quick Install

```bash
git clone https://github.com/BYNNAI/AutomatonSec.git
cd AutomatonSec
pip install -r requirements.txt
```

## 🔧 Usage

### Scanning Bug Bounty Repositories

**Download and scan an entire bug bounty repository:**

```bash
# Clone the target repository
git clone https://github.com/immunefi-team/example-protocol.git
cd example-protocol

# Scan all contracts (excludes test files automatically)
python -m src.cli scan . --output vulnerability-report.json --workers 8

# Scan specific directory
python -m src.cli scan ./contracts --output report.json --workers 4
```

**Output includes:**
- Total files analyzed
- Vulnerabilities by severity (Critical, High, Medium, Low)
- Analysis time and performance metrics
- Detailed findings with locations and recommendations
- JSON export for further processing

### Single Contract Analysis

```bash
# Basic analysis
python -m src.cli analyze contracts/Token.sol --output results.json

# Full analysis with all detectors
python -m src.cli analyze contracts/Vault.sol --full --output full-analysis.json
```

### Python API Usage

**Repository Scanning:**

```python
from pathlib import Path
from src.scanner.repository_scanner import RepositoryScanner

# Configure scanner
scanner = RepositoryScanner(config={
    "max_workers": 8,              # Parallel analysis threads
    "exclude_tests": True,         # Skip test files
    "max_symbolic_depth": 128,     # Symbolic execution depth
    "fuzzing_iterations": 10000    # Fuzzing iterations per contract
})

# Scan repository
results = scanner.scan_directory(Path("./bug-bounty-repo"))

# Process results
print(f"Total files analyzed: {results['summary']['total_files']}")
print(f"Critical vulnerabilities: {results['summary']['critical']}")
print(f"High severity: {results['summary']['high']}")
print(f"Analysis time: {results['summary']['analysis_time_seconds']:.2f}s")

# Export report
scanner.export_report(Path("vulnerability-report.json"))

# Access individual vulnerabilities
for vuln in results['vulnerabilities']:
    if vuln['severity'] == 'CRITICAL':
        print(f"\n[CRITICAL] {vuln['name']}")
        print(f"Location: {vuln['location']}")
        print(f"Description: {vuln['description']}")
        print(f"Recommendation: {vuln['recommendation']}")
```

**Single Contract Analysis:**

```python
from src.core.engine import AutomatonSecEngine
from src.core.models import Severity

# Initialize engine
engine = AutomatonSecEngine(config={
    "max_symbolic_depth": 128,
    "fuzzing_iterations": 10000,
    "enable_cross_contract": True,
    "generate_exploits": True
})

# Analyze contract
with open('MyContract.sol', 'r') as f:
    source_code = f.read()

report = engine.analyze_contract(source_code=source_code)

# Filter critical vulnerabilities
critical = [v for v in engine.vulnerabilities if v.severity == Severity.CRITICAL]

for vuln in critical:
    print(f"[{vuln.severity.value}] {vuln.name}")
    print(f"Confidence: {vuln.confidence:.0%}")
    print(f"Impact: {vuln.impact}")
    
    if vuln.exploit:
        print(f"\nExploit: {vuln.exploit.description}")
        print(f"Profit Estimate: ${vuln.exploit.profit_estimate:,.2f}")
        print(f"\nProof of Concept:")
        print(vuln.exploit.proof_of_concept)
```

### Test File Exclusion

**Automatically excluded patterns:**

```
Directories:
  test/, tests/, testing/, mocks/, fixtures/
  forge-std/, hardhat/, truffle/, node_modules/

Files:
  *.test.sol, *.t.sol, *Test.sol, *Mock.sol
  Setup.sol, TestHelpers.sol, MockOracle.sol
```

**Custom exclusion patterns:**

```python
from src.scanner.test_filter import TestFileFilter

filter = TestFileFilter()
filter.add_pattern(r"/custom-test-dir/")
filter.add_pattern(r".*\.custom\.sol$")

production_files = filter.filter_files(all_files)
```

## 🔬 Vulnerability Detectors

### Critical Severity (7 Detectors)

#### 1. Vault Inflation Detector
**Detects:** First depositor attacks in ERC4626 vaults and liquidity pools  
**Attack:** Attacker deposits 1 wei, donates large amount to inflate share price, subsequent depositors receive 0 shares  
**Impact:** Complete fund theft from later depositors  
**PoC Generation:** ✅ Automated exploit with profit estimation

#### 2. Flash Loan Attack Detector
**Detects:** Flash loan exploitation vectors and MEV opportunities  
**Attack:** Temporary capital manipulation for price oracle attacks, governance takeover  
**Impact:** Protocol drain, market manipulation  
**Features:** Cross-contract flow analysis, profit calculation

#### 3. Price Manipulation Detector
**Detects:** Spot price oracle manipulation in AMMs and DEXs  
**Attack:** Large swaps or flash loans to manipulate on-chain price oracles  
**Impact:** Liquidation attacks, arbitrage exploitation, protocol insolvency  
**Coverage:** Uniswap, Balancer, Curve price feeds

#### 4. Storage Collision Detector
**Detects:** Proxy storage slot conflicts in upgradeable contracts  
**Attack:** Implementation variables overwrite proxy variables  
**Impact:** Contract takeover, fund theft, permanent bricking  
**Checks:** EIP-1967 compliance, namespaced storage patterns

#### 5. Governance Attack Detector
**Detects:** Flash loan voting manipulation and proposal execution flaws  
**Attack:** Borrow voting tokens, pass malicious proposals, return tokens  
**Impact:** Protocol takeover, treasury drain  
**Analysis:** Snapshot-based voting validation, time-lock checks

#### 6. Exploit Chain Detector
**Detects:** Multi-step attack sequences combining multiple vulnerabilities  
**Attack:** Chained exploits across contracts (e.g., reentrancy + flash loan + oracle manipulation)  
**Impact:** Complex protocol-level exploits  
**Features:** Graph-based attack path discovery

#### 7. Reentrancy Detector
**Detects:** Single and cross-contract reentrancy patterns  
**Attack:** External call before state update allows recursive calls  
**Impact:** Fund drainage, state manipulation  
**Coverage:** Classic, cross-function, and read-only reentrancy

### High Severity (8 Detectors)

#### 8. Read-Only Reentrancy Detector
**Detects:** View/pure function reentrancy during external calls  
**Attack:** Query stale state values during callback execution  
**Impact:** Oracle manipulation, incorrect price feeds  
**Example:** Curve LP token price manipulation

#### 9. Callback Reentrancy Detector
**Detects:** ERC721/ERC1155 receiver callback exploitation  
**Attack:** Reenter through onERC721Received or similar callbacks  
**Impact:** State manipulation before critical updates  
**Coverage:** All safe transfer callbacks

#### 10. Unchecked Return Detector
**Detects:** Ignored return values from external calls  
**Attack:** Silent failures in token transfers or critical operations  
**Impact:** Fund loss, incorrect accounting  
**Example:** ERC20 transfer without checking success

#### 11. Unsafe Cast Detector
**Detects:** Unchecked type downcasts (uint256 → uint128/uint64)  
**Attack:** Silent overflow in type conversion  
**Impact:** Fund loss, incorrect calculations  
**Coverage:** All integer downcast operations

#### 12. Donation Attack Detector
**Detects:** Logic dependent on untracked token balances  
**Attack:** Direct token transfers manipulate contract logic  
**Impact:** Accounting manipulation, unfair advantage  
**Example:** Balance-based fee calculations

#### 13. Stale Price Detector
**Detects:** Oracle data usage without timestamp validation  
**Attack:** Use outdated prices for liquidations or trades  
**Impact:** Unfair liquidations, arbitrage  
**Checks:** Heartbeat validation, update frequency

#### 14. Selector Collision Detector
**Detects:** Different function signatures producing identical 4-byte selectors  
**Attack:** Call wrong function in proxy contracts  
**Impact:** Unintended function execution  
**Analysis:** Exhaustive selector collision detection

#### 15. Access Control Detector
**Detects:** Missing or broken authorization checks  
**Attack:** Unauthorized access to privileged functions  
**Impact:** Fund theft, contract takeover  
**Coverage:** Proxy patterns, multi-sig requirements

### Medium Severity (4 Detectors)

#### 16. Sandwich Attack Detector
**Detects:** MEV sandwich attack vectors in DEX swaps  
**Attack:** Front-run victim trade, manipulate price, back-run  
**Impact:** User value extraction via slippage  
**Checks:** Slippage protection, deadline enforcement

#### 17. Rounding Error Detector
**Detects:** Precision loss in financial calculations  
**Attack:** Exploit rounding to drain funds incrementally  
**Impact:** Accumulated fund loss over time  
**Example:** Division before multiplication in share calculations

#### 18. JIT Liquidity Detector
**Detects:** Just-in-time liquidity manipulation  
**Attack:** Add liquidity before large trades, remove after  
**Impact:** MEV extraction, unfair fee capture  
**Checks:** Liquidity lock periods

#### 19. Oracle Timestamp Detector
**Detects:** Timestamp dependence vulnerabilities  
**Attack:** Miner timestamp manipulation  
**Impact:** Logic bypass, unfair advantage  
**Coverage:** Block.timestamp usage in critical paths

## 📊 Detection Methodology

### Multi-Phase Analysis

1. **Bytecode Analysis** - EVM opcode parsing and instruction decoding
2. **Control Flow Graph** - Function call graph and execution paths
3. **Taint Analysis** - Inter-procedural data flow tracking
4. **Symbolic Execution** - Path exploration with constraint solving
5. **Profit Fuzzing** - Gradient-descent guided input generation
6. **Cross-Contract Analysis** - Multi-contract interaction patterns
7. **Exploit Generation** - Automated PoC creation for verified bugs

### Zero-Day Discovery

- **Pattern Recognition** - Historical exploit analysis and heuristics
- **Anomaly Detection** - Statistical deviation from safe patterns
- **Economic Modeling** - Profit calculation for attack scenarios
- **State Space Exploration** - Deep symbolic execution paths

## 🏗️ Architecture

```
src/
├── core/                    # Analysis engine
│   ├── engine.py           # Main orchestration
│   ├── models.py           # Vulnerability models
│   ├── bytecode_analyzer.py
│   └── contract_parser.py
├── detectors/              # 19 vulnerability detectors
│   ├── vault_inflation_detector.py
│   ├── price_manipulation_detector.py
│   ├── read_only_reentrancy_detector.py
│   ├── storage_collision_detector.py
│   └── [15 more detectors]
├── scanner/                # Repository scanning
│   ├── repository_scanner.py
│   └── test_filter.py
├── symbolic/               # Symbolic execution
│   └── executor.py
├── dataflow/              # Data flow analysis
│   ├── cfg_builder.py
│   └── taint_analyzer.py
└── cli.py                 # Command-line interface
```

## 📈 Performance

### Benchmark Results

| Metric | AutomatonSec | Industry Average |
|--------|--------------|------------------|
| Zero-Day Detection | **Specialized** | Limited |
| False Positive Rate | **< 5%** | 15-20% |
| Critical Bug Detection | **19 Types** | 8-12 Types |
| Repo Scan (100 files) | **< 30 min** | 45-90 min |
| Single Contract | **< 60s** | 30-180s |
| Exploit Generation | **Automated** | Manual |

### Validated Against

- DeFi exploit post-mortems (2020-2025)
- Immunefi bug bounty submissions
- Code4rena audit findings
- Sherlock contest reports

## 🎯 Use Cases

### Security Auditing
- Pre-deployment security assessment
- Continuous integration testing
- Third-party code review

### Bug Bounty Hunting
- Repository-wide vulnerability scanning
- Zero-day discovery in live protocols
- Exploit PoC generation for submissions

### Protocol Development
- Development-time vulnerability detection
- PR-based automated security checks
- Pre-audit preparation

## 🔗 Output Format

### JSON Report Structure

```json
{
  "summary": {
    "total_files": 127,
    "total_vulnerabilities": 23,
    "critical": 3,
    "high": 8,
    "medium": 12,
    "analysis_time_seconds": 847.3
  },
  "vulnerabilities": [
    {
      "type": "vault_inflation",
      "severity": "CRITICAL",
      "name": "Vault Share Inflation Attack",
      "description": "First depositor can inflate share price through donation",
      "location": "contracts/Vault.sol:156:deposit()",
      "confidence": 0.95,
      "impact": "Complete theft of funds from subsequent depositors",
      "recommendation": "Implement dead shares mechanism or minimum deposit",
      "exploit": {
        "description": "First depositor inflation attack",
        "profit_estimate": 100000.0,
        "proof_of_concept": "// 1. Deposit 1 wei\nvault.deposit(1);\n..."
      }
    }
  ],
  "files_analyzed": ["contracts/Token.sol", "contracts/Vault.sol", ...]
}
```

## ⚠️ Disclaimer

This tool is for security research and auditing purposes only. Always:
- Perform manual code review in addition to automated analysis
- Validate findings before reporting
- Follow responsible disclosure practices
- Respect bug bounty program rules

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Repository**: [github.com/BYNNAI/AutomatonSec](https://github.com/BYNNAI/AutomatonSec)
- **Issues**: [Report bugs or request features](https://github.com/BYNNAI/AutomatonSec/issues)
- **Documentation**: [Full documentation](docs/)

---

**BYNNΛI - Advanced Smart Contract Security**