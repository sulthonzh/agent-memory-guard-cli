# Agent Memory Guard CLI

🛡️ **AI Agent Memory Integrity CLI** - Protects AI agent persistent memory from poisoning attacks with real-time validation, backup, and restoration capabilities.

## 🚨 The Problem

Memory poisoning is a critical security threat where attackers corrupt AI agent memory states, leading to:
- Data exfiltration
- Malicious behavior injection  
- System hijacking
- Trust degradation

**Stats:** 98% injection success rate (MINJA research), Microsoft caught 31 companies poisoning AI memory in 60 days, OWASP ASI06: Memory Poisoning in Top 10 for Agentic Applications.

## ✨ Features

- 🔒 **Memory Integrity Validation** - Cryptographic hashing (SHA-256) to detect tampering
- 🚨 **Attack Detection** - Identifies injection attempts, anomalies, and corruption
- 💾 **Automatic Backups** - Creates and manages secure memory state backups
- 🔄 **State Restoration** - Rollback to known-good memory states
- 👁️ **Real-time Monitoring** - Continuous memory integrity monitoring
- 🔗 **Framework Integration** - Built-in support for LangChain, LlamaIndex, CrewAI
- 📊 **Detailed Reporting** - Comprehensive security scoring and issue analysis

## 🚀 Quick Start

### Installation

```bash
npm install -g agent-memory-guard-cli
```

### Basic Usage

```bash
# Validate memory integrity
agent-memory-guard validate ./agent-memory.json

# Validate with backup creation
agent-memory-guard validate ./agent-memory.json --backup

# Validate with previous state comparison
agent-memory-guard validate ./agent-memory.json --previous ./memory-previous.json

# Start real-time monitoring
agent-memory-guard monitor ./agent-memory.json --interval 5

# Create backup
agent-memory-guard backup ./agent-memory.json

# Restore from backup
agent-memory-guard restore ./agent-memory.json --list
agent-memory-guard restore ./agent-memory.json --timestamp 1672531200000
```

## 📖 Detailed Usage

### Validation

```bash
# Basic validation
agent-memory-guard validate ./memory.json

# Verbose output with detailed analysis
agent-memory-guard validate ./memory.json --verbose

# Create backup and save report
agent-memory-guard validate ./memory.json --backup --output security-report.json
```

**Validation Output:**
```
🛡️  Validating memory: /path/to/agent-memory.json
📊 Memory Integrity Report
═══════════════════════════════════════════════════════
🔒 Security Score: 95/100
✅ Valid: YES
🚨 Issues Found: 1

📋 Issue Summary:
  1. ⚠️ 🟠 ANOMALY: Significant memory change detected: 45.2%
     💡 Suggestion: Verify this change is legitimate. Consider restoring from backup.

📈 Current State:
   ID: 550e8400-e29b-41d4-a716-446655440000
   Timestamp: 2026-06-17T14:30:00.000Z
   Size: 2.5 KB
   Hash: a1b2c3d4...
```

### Monitoring

```bash
# Monitor memory every 30 seconds
agent-memory-guard monitor ./memory.json --interval 30 --anomaly-threshold 0.2

# Monitor with logging
agent-memory-guard monitor ./memory.json --interval 10 --log security-alerts.log
```

**Monitoring Output:**
```
👁️  Starting real-time monitoring: /path/to/agent-memory.json
⏱️  Interval: 30s
📊 Anomaly threshold: 0.2

🔍 Check #1 - 2026-06-17T14:30:00.000Z
✅ Memory integrity verified (95/100)

🔍 Check #2 - 2026-06-17T14:30:30.000Z
🚨 SECURITY ALERT: Memory integrity compromised!
🚨 SECURITY ALERT: Memory integrity compromised!
🔒 Security Score: 45/100
✅ Valid: NO
🚨 Issues Found: 3
📋 Issue Summary:
  1. 🚨 🔴 INJECTION: Suspicious memory key detected: system_prompt
     💡 Suggestion: Review this key for potential injection attempts
  2. 💥 🔴 CORRUPTION: Circular reference detected in memory at path: data.self
     💡 Suggestion: Remove circular references to prevent memory corruption
  3. ⚠️ 🟠 ANOMALY: Significant memory change detected: 78.5%
     💡 Suggestion: Verify this change is legitimate. Consider restoring from backup
```

### Backup Management

```bash
# Create backup with custom settings
agent-memory-guard backup ./memory.json --directory ./secure-backups --name custom-backup

# List available backups
agent-memory-guard restore ./memory.json --list

# Restore from specific backup
agent-memory-guard restore ./memory.json --timestamp 1672531200000
```

### Framework Integration

```bash
# Generate LangChain integration code
agent-memory-guard integrate --framework langchain --output langchain-integration.js

# Generate LlamaIndex integration code  
agent-memory-guard integrate --framework llamaindex --output llamaindex-integration.js

# Generate CrewAI integration code
agent-memory-guard integrate --framework crewai --output crewai-integration.js

# Show available frameworks
agent-memory-guard integrate
```

## 🔧 Framework Integration

### LangChain

```javascript
import { SecureMemory } from './langchain-integration.js';

const secureMemory = new SecureMemory('./agent-memory.json');
await secureMemory.loadMemory();
const memory = await secureMemory.getMemory();
await secureMemory.setMemory(updatedMemory);
```

### LlamaIndex

```javascript
import { SecureMemoryManager } from './llamaindex-integration.js';

const memoryManager = new SecureMemoryManager('./llamaindex-memory.json');
const memory = await memoryManager.load();
await memoryManager.save(memory);
```

### CrewAI

```javascript
import { SecureMemoryHandler } from './crewai-integration.js';

const secureMemory = new SecureMemoryHandler('./crewai-memory.json');
await secureMemory.initialize();
const memory = secureMemory.get();
secureMemory.set(memory);
await secureMemory.save();
```

## 🛡️ Security Features

### Attack Detection

1. **Memory Corruption Detection**
   - Circular reference detection
   - Structure validation
   - Size anomaly detection

2. **Injection Attack Detection**
   - Suspicious key patterns (prompt, instruction, override, etc.)
   - Sensitive data scanning (passwords, API keys, tokens)
   - Malicious content patterns

3. **Anomaly Detection**
   - State change analysis
   - Frequency pattern detection
   - Statistical deviation monitoring

4. **Tampering Detection**
   - File integrity verification
   - Real-time change monitoring
   - Cryptographic validation

### Protection Mechanisms

- **Cryptographic Hashing**: SHA-256 memory state validation
- **Immutable Backups**: Versioned memory state preservation
- **Real-time Monitoring**: Continuous integrity checking
- **Automated Rollback**: Restore from known-good states
- **Alert System**: Immediate notification of suspicious activity

## 🔧 Configuration

### Environment Variables

```bash
AGENT_MEMORY_BACKUP_DIR=./memory-backups
AGENT_MEMORY_MAX_BACKUPS=10
AGENT_MEMORY_ANOMALY_THRESHOLD=0.3
AGENT_MEMORY_HASH_ALGORITHM=sha256
```

### Custom Configuration

```javascript
import { MemoryValidator } from './memory-validator.js';

const validator = new MemoryValidator({
  backupDirectory: './secure-backups',
  maxBackups: 20,
  hashAlgorithm: 'sha512',
  sensitivePatterns: [
    /password/i,
    /api[_-]?key/i,
    /secret/i,
    /token/i
  ],
  anomalyThreshold: 0.2
});
```

## 📊 API Reference

### MemoryValidator

#### Constructor
```typescript
new MemoryValidator(config?: Partial<MemoryConfig>)
```

#### Methods

- `validateMemoryState(memoryPath: string, previousState?: MemoryState): Promise<ValidationResult>`
- `backupMemory(memoryPath: string, state: MemoryState): Promise<string>`
- `restoreFromBackup(memoryPath: string, timestamp?: number): Promise<string>`
- `getAvailableBackups(): Promise<BackupInfo[]>`

### Types

#### ValidationResult
```typescript
interface ValidationResult {
  isValid: boolean;
  issues: Array<{
    type: 'corruption' | 'injection' | 'anomaly' | 'tampering';
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    suggestion: string;
    evidence?: any;
  }>;
  score: number; // 0-100
  currentState?: MemoryState;
  previousState?: MemoryState;
}
```

#### MemoryState
```typescript
interface MemoryState {
  id: string;
  timestamp: number;
  hash: string;
  data: any;
  metadata: {
    version: string;
    framework?: string;
    size: number;
    checksumAlgorithm: string;
  };
}
```

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Build project
npm run build

# Development mode
npm run dev
```

## 🚨 Security Considerations

- **Never commit sensitive memory states to version control**
- **Use backup rotation to prevent storage exhaustion**
- **Monitor backup directories for unauthorized access**
- **Regular integrity checks in production environments**
- **Network isolation for critical memory storage**

## 🔗 Related Projects

- [OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/) - Enterprise memory protection
- [LangChain](https://github.com/langchain-ai/langchain) - LLM application framework
- [LlamaIndex](https://github.com/run-llama/llama_index) - LLM data framework
- [CrewAI](https://github.com/joaomdmoura/crewAI) - Collaborative AI agents

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

- 🐛 [Report bugs](https://github.com/sulthonzh/agent-memory-guard-cli/issues)
- 💡 [Feature requests](https://github.com/sulthonzh/agent-memory-guard-cli/issues)
- 📖 [Documentation](https://github.com/sulthonzh/agent-memory-guard-cli/wiki)

---

**Built with ❤️ to protect AI systems from memory poisoning attacks**