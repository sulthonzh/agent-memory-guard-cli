#!/usr/bin/env node

import { Command } from 'commander';
import { MemoryValidator } from './memory-validator.js';
import fs from 'fs/promises';
import path from 'path';

const program = new Command();

program
  .name('agent-memory-guard')
  .description('AI Agent Memory Integrity CLI - Protects agent memory from poisoning attacks')
  .version('1.0.0');

program
  .command('validate')
  .description('Validate memory integrity and detect potential attacks')
  .argument('<memory-path>', 'Path to the memory file')
  .option('-b, --backup', 'Create backup of current memory state')
  .option('-p, --previous [previous-state]', 'Path to previous memory state for comparison')
  .option('-o, --output [output-file]', 'Path to save validation report')
  .option('-v, --verbose', 'Show detailed validation output')
  .action(async (memoryPath: string, options) => {
    try {
      const validator = new MemoryValidator();
      const absolutePath = path.resolve(memoryPath);
      
      console.log(`🛡️  Validating memory: ${absolutePath}`);
      
      let previousState: any;
      if (options.previous) {
        const previousData = await fs.readFile(options.previous, 'utf-8');
        previousState = JSON.parse(previousData);
        console.log(`📊 Comparing with previous state: ${options.previous}`);
      }

      const result = await validator.validateMemoryState(absolutePath, previousState);
      
      // Create backup if requested
      let backupPath: string | undefined;
      if (options.backup && result.currentState) {
        backupPath = await validator.backupMemory(absolutePath, result.currentState);
        console.log(`💾 Backup created: ${backupPath}`);
      }

      // Display results
      if (options.verbose) {
        displayVerboseResult(result);
      } else {
        displaySummaryResult(result);
      }

      // Save report if requested
      if (options.output) {
        await saveReport(result, options.output);
        console.log(`📄 Report saved: ${options.output}`);
      }

      // Exit with appropriate code
      process.exit(result.isValid ? 0 : 1);
      
    } catch (error) {
      console.error('❌ Validation failed:', error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('backup')
  .description('Create backup of memory state')
  .argument('<memory-path>', 'Path to the memory file')
  .option('-d, --directory [backup-dir]', 'Directory to store backups')
  .option('-n, --name [backup-name]', 'Custom backup name')
  .action(async (memoryPath: string, options) => {
    try {
      const validator = new MemoryValidator({
        backupDirectory: options.directory || './memory-backups'
      });
      
      const absolutePath = path.resolve(memoryPath);
      const memoryData = await fs.readFile(absolutePath, 'utf-8');
      const data = JSON.parse(memoryData);
      
      const state = validator['createMemoryState'](data, absolutePath);
      const backupPath = await validator.backupMemory(absolutePath, state);
      
      console.log(`✅ Memory backed up successfully: ${backupPath}`);
      console.log(`📊 State ID: ${state.id}`);
      console.log(`⏰ Timestamp: ${new Date(state.timestamp).toISOString()}`);
      console.log(`🔒 Hash: ${state.hash}`);
      
    } catch (error) {
      console.error('❌ Backup failed:', error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('restore')
  .description('Restore memory from backup')
  .argument('<memory-path>', 'Path to restore the memory file')
  .option('-b, --backup [backup-path]', 'Path to backup file to restore')
  .option('-t, --timestamp [timestamp]', 'Timestamp of backup to restore')
  .option('-l, --list', 'List available backups')
  .action(async (memoryPath: string, options) => {
    try {
      const validator = new MemoryValidator();
      const absolutePath = path.resolve(memoryPath);
      
      if (options.list) {
        const backups = await validator['getAvailableBackups']();
        console.log('📁 Available backups:');
        backups.forEach((backup, index) => {
          console.log(`  ${index + 1}. ${path.basename(backup.path)}`);
          console.log(`     Timestamp: ${new Date(backup.timestamp).toISOString()}`);
          console.log(`     ID: ${backup.id}`);
          console.log(`     Size: ${(backup.mtime.getTime() / 1024).toFixed(2)} KB`);
          console.log('');
        });
        return;
      }

      const restorePath = await validator.restoreFromBackup(absolutePath, options.timestamp as any);
      console.log(`✅ Memory restored successfully from: ${restorePath}`);
      
    } catch (error) {
      console.error('❌ Restore failed:', error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('monitor')
  .description('Start real-time memory monitoring')
  .argument('<memory-path>', 'Path to monitor')
  .option('-i, --interval [interval]', 'Monitoring interval in seconds', '5')
  .option('-a, --anomaly-threshold [threshold]', 'Anomaly detection threshold (0-1)', '0.3')
  .option('-l, --log [log-file]', 'Log file path')
  .action(async (memoryPath: string, options) => {
    try {
      const interval = parseInt(options.interval) * 1000;
      const anomalyThreshold = parseFloat(options.anomalyThreshold);
      
      const validator = new MemoryValidator({ anomalyThreshold });
      const absolutePath = path.resolve(memoryPath);
      
      console.log(`👁️  Starting real-time monitoring: ${absolutePath}`);
      console.log(`⏱️  Interval: ${options.interval}s`);
      console.log(`📊 Anomaly threshold: ${anomalyThreshold}`);
      
      let previousState: any;
      let monitoringCount = 0;
      
      const monitoringLoop = async () => {
        try {
          monitoringCount++;
          console.log(`\\n🔍 Check #${monitoringCount} - ${new Date().toISOString()}`);
          
          const result = await validator.validateMemoryState(absolutePath, previousState);
          
          if (!result.isValid) {
            console.log(`🚨 SECURITY ALERT: Memory integrity compromised!`);
            displaySummaryResult(result);
            
            if (options.log) {
              await saveReport(result, options.log);
              console.log(`📄 Alert logged to: ${options.log}`);
            }
          } else {
            console.log(`✅ Memory integrity verified (${result.score}/100)`);
          }
          
          // Update previous state for next iteration
          if (result.currentState) {
            previousState = result.currentState;
          }
          
        } catch (error) {
          console.error(`❌ Monitoring error: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      };
      
      // Initial check
      await monitoringLoop();
      
      // Set up periodic monitoring
      setInterval(monitoringLoop, interval);
      
      // Keep the process running
      process.on('SIGINT', () => {
        console.log('\\n🛑 Monitoring stopped');
        process.exit(0);
      });
      
    } catch (error) {
      console.error('❌ Monitor failed:', error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('integrate')
  .description('Setup integration with AI frameworks')
  .option('-f, --framework <framework>', 'Framework to integrate with (langchain|llamaindex|crewai)')
  .option('-o, --output [output-file]', 'Output file for integration code')
  .action(async (options) => {
    try {
      if (!options.framework) {
        console.log('Available frameworks:');
        console.log('  langchain  - LangChain integration');
        console.log('  llamaindex - LlamaIndex integration');
        console.log('  crewai    - CrewAI integration');
        return;
      }

      const integrations = {
        langchain: generateLangChainIntegration(),
        llamaindex: generateLlamaIndexIntegration(),
        crewai: generateCrewAIIntegration()
      };

      if (!integrations[options.framework as keyof typeof integrations]) {
        console.error(`❌ Unknown framework: ${options.framework}`);
        process.exit(1);
      }

      const integrationCode = integrations[options.framework as keyof typeof integrations];
      
      if (options.output) {
        await fs.writeFile(options.output, integrationCode);
        console.log(`✅ Integration code saved to: ${options.output}`);
      } else {
        console.log('🔧 Integration code:');
        console.log(integrationCode);
      }
      
    } catch (error) {
      console.error('❌ Integration setup failed:', error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

function displaySummaryResult(result: any) {
  console.log(`\\n📊 Memory Integrity Report`);
  console.log(`═══════════════════════════════════════════════════════`);
  console.log(`🔒 Security Score: ${result.score}/100`);
  console.log(`✅ Valid: ${result.isValid ? 'YES' : 'NO'}`);
  console.log(`🚨 Issues Found: ${result.issues.length}`);
  
  if (result.issues.length > 0) {
    console.log(`\\n📋 Issue Summary:`);
    result.issues.forEach((issue: any, index: number) => {
      const icons: any = {
        corruption: '💥',
        injection: '🚨',
        anomaly: '⚠️',
        tampering: '🔍'
      };
      const colors: any = {
        low: '🟢',
        medium: '🟡',
        high: '🟠',
        critical: '🔴'
      };
      
      console.log(`  ${index + 1}. ${icons[issue.type]} ${colors[issue.severity]} ${issue.severity.toUpperCase()}: ${issue.message}`);
      if (issue.suggestion) {
        console.log(`     💡 Suggestion: ${issue.suggestion}`);
      }
    });
  }
  
  if (result.currentState) {
    console.log(`\\n📈 Current State:`);
    console.log(`   ID: ${result.currentState.id}`);
    console.log(`   Timestamp: ${new Date(result.currentState.timestamp).toISOString()}`);
    console.log(`   Size: ${formatBytes(result.currentState.metadata.size)}`);
    console.log(`   Hash: ${result.currentState.hash.substring(0, 16)}...`);
  }
}

function displayVerboseResult(result: any) {
  displaySummaryResult(result);
  
  if (result.issues.length > 0) {
    console.log(`\\n🔍 Detailed Analysis:`);
    result.issues.forEach((issue: any, index: number) => {
      console.log(`\\n${index + 1}. ${issue.type.toUpperCase()} ISSUE (${issue.severity})`);
      console.log(`   Message: ${issue.message}`);
      console.log(`   Suggestion: ${issue.suggestion}`);
      if (issue.evidence) {
        console.log(`   Evidence: ${JSON.stringify(issue.evidence, null, 2)}`);
      }
    });
  }
  
  if (result.currentState && result.previousState) {
    console.log(`\\n📊 Change Analysis:`);
    console.log(`   Time Delta: ${result.currentState.timestamp - result.previousState.timestamp}ms`);
    console.log(`   Size Delta: ${formatBytes(result.currentState.metadata.size - result.previousState.metadata.size)}`);
  }
}

async function saveReport(result: any, outputPath: string) {
  const report = {
    timestamp: new Date().toISOString(),
    validation: {
      isValid: result.isValid,
      score: result.score,
      issuesCount: result.issues.length
    },
    issues: result.issues,
    currentState: result.currentState,
    previousState: result.previousState,
    summary: {
      totalChecks: result.issues.length,
      criticalIssues: result.issues.filter((i: any) => i.severity === 'critical').length,
      highIssues: result.issues.filter((i: any) => i.severity === 'high').length,
      recommendation: result.isValid ? 'Memory is secure' : 'Immediate investigation required'
    }
  };

  await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
}

function formatBytes(bytes: number): string {
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  if (bytes === 0) return '0 Bytes';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
}

function generateLangChainIntegration() {
  return `import { MemoryValidator } from './memory-validator.js';

// LangChain Memory Integration
export class SecureMemory {
  private validator: MemoryValidator;
  private memory: any;
  private memoryPath: string;

  constructor(memoryPath: string) {
    this.memoryPath = memoryPath;
    this.validator = new MemoryValidator();
  }

  async loadMemory(): Promise<void> {
    const fs = await import('fs/promises');
    const data = await fs.readFile(this.memoryPath, 'utf-8');
    this.memory = JSON.parse(data);
    
    const result = await this.validator.validateMemoryState(this.memoryPath);
    if (!result.isValid) {
      throw new Error('Memory integrity compromised: ' + result.issues.map(i => i.message).join(', '));
    }
  }

  async saveMemory(): Promise<void> {
    const fs = await import('fs/promises');
    await fs.writeFile(this.memoryPath, JSON.stringify(this.memory, null, 2));
    
    const result = await this.validator.validateMemoryState(this.memoryPath);
    if (!result.isValid) {
      throw new Error('Memory tampering detected during save');
    }
  }

  async getMemory(): Promise<any> {
    return this.memory;
  }

  async setMemory(data: any): Promise<void> {
    this.memory = data;
    await this.saveMemory();
  }
}

// Usage example
const secureMemory = new SecureMemory('./agent-memory.json');
await secureMemory.loadMemory();
const memory = await secureMemory.getMemory();
`;
}

function generateLlamaIndexIntegration() {
  return `import { MemoryValidator } from './memory-validator.js';

// LlamaIndex Memory Integration
export class SecureMemoryManager {
  private validator: MemoryValidator;
  private memory: any;
  private memoryPath: string;

  constructor(memoryPath: string) {
    this.memoryPath = memoryPath;
    this.validator = new MemoryValidator();
  }

  async load(): Promise<any> {
    const fs = await import('fs/promises');
    const data = await fs.readFile(this.memoryPath, 'utf-8');
    this.memory = JSON.parse(data);
    
    const result = await this.validator.validateMemoryState(this.memoryPath);
    if (!result.isValid) {
      console.warn('Memory integrity issues detected:', result.issues);
    }
    
    return this.memory;
  }

  async save(data?: any): Promise<void> {
    if (data) this.memory = data;
    
    const fs = await import('fs/promises');
    await fs.writeFile(this.memoryPath, JSON.stringify(this.memory, null, 2));
    
    const result = await this.validator.validateMemoryState(this.memoryPath);
    if (!result.isValid) {
      throw new Error('Memory validation failed after save');
    }
  }

  async get(): Promise<any> {
    return this.memory;
  }

  async set(data: any): Promise<void> {
    await this.save(data);
  }
}

// Usage example
const memoryManager = new SecureMemoryManager('./llamaindex-memory.json');
const memory = await memoryManager.load();
await memoryManager.save(memory);
`;
}

function generateCrewAIIntegration() {
  return `import { MemoryValidator } from './memory-validator.js';

// CrewAI Memory Integration
export class SecureMemoryHandler {
  private validator: MemoryValidator;
  private memoryPath: string;
  private memory: any;

  constructor(memoryPath: string) {
    this.memoryPath = memoryPath;
    this.validator = new MemoryValidator();
  }

  async initialize(): Promise<void> {
    await this.load();
  }

  async load(): Promise<void> {
    const fs = await import('fs/promises');
    try {
      const data = await fs.readFile(this.memoryPath, 'utf-8');
      this.memory = JSON.parse(data);
      
      const result = await this.validator.validateMemoryState(this.memoryPath);
      if (!result.isValid) {
        console.warn('⚠️ Memory security issues detected');
        result.issues.forEach((issue: any) => {
          console.warn(\`   - \${issue.severity}: \${issue.message}\`);
        });
      }
    } catch (error) {
      // Initialize empty memory if it doesn't exist
      this.memory = { created: new Date().toISOString() };
      await this.save();
    }
  }

  async save(): Promise<void> {
    const fs = await import('fs/promises');
    this.memory.lastUpdated = new Date().toISOString();
    await fs.writeFile(this.memoryPath, JSON.stringify(this.memory, null, 2));
    
    const result = await this.validator.validateMemoryState(this.memoryPath);
    if (!result.isValid) {
      throw new Error('Memory validation failed after save');
    }
  }

  get(): any {
    return this.memory;
  }

  set(data: any): void {
    this.memory = data;
  }

  async clear(): Promise<void> {
    this.memory = { cleared: new Date().toISOString() };
    await this.save();
  }
}

// Usage example
const secureMemory = new SecureMemoryHandler('./crewai-memory.json');
await secureMemory.initialize();
const memory = secureMemory.get();
secureMemory.set(memory);
await secureMemory.save();
`;
}

program.parse();