import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

export interface MemoryState {
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

export interface ValidationResult {
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
  previousState?: MemoryState | undefined;
}

export interface MemoryConfig {
  backupDirectory: string;
  maxBackups: number;
  hashAlgorithm: string;
  sensitivePatterns: RegExp[];
  anomalyThreshold: number;
}

export class MemoryValidator {
  private config: MemoryConfig;

  constructor(config: Partial<MemoryConfig> = {}) {
    this.config = {
      backupDirectory: './memory-backups',
      maxBackups: 10,
      hashAlgorithm: 'sha256',
      sensitivePatterns: [
        /password/i,
        /api[_-]?key/i,
        /secret/i,
        /token/i,
        /bearer/i,
        /authorization/i,
        /private[_-]?key/i,
        /access[_-]?token/i
      ],
      anomalyThreshold: 0.3, // 30% change threshold
      ...config
    };
  }

  async validateMemoryState(memoryPath: string, previousState?: MemoryState): Promise<ValidationResult> {
    try {
      // Read current memory state
      const memoryData = await fs.readFile(memoryPath, 'utf-8');
      const parsedData = JSON.parse(memoryData);
      
      // Generate hash for current state
      const currentState = this.createMemoryState(parsedData, memoryPath);
      
      // Validate basic structure
      const structureIssues = this.validateMemoryStructure(parsedData);
      
      // Detect anomalies
      const anomalyIssues = previousState ? 
        this.detectAnomalies(currentState, previousState) : [];
      
      // Detect potential injection
      const injectionIssues = this.detectInjectionAttempts(parsedData);
      
      // Detect tampering
      const tamperingIssues = await this.detectTampering(currentState, memoryPath);
      
      // Consolidate all issues
      const allIssues = [...structureIssues, ...anomalyIssues, ...injectionIssues, ...tamperingIssues];
      
      // Calculate score
      const score = this.calculateSecurityScore(allIssues);
      
      return {
        isValid: allIssues.length === 0,
        issues: allIssues,
        score,
        currentState: currentState ? currentState : undefined,
        previousState: previousState ? previousState : undefined
      };
      
    } catch (error) {
      return {
        isValid: false,
        issues: [{
          type: 'corruption',
          severity: 'critical',
          message: `Memory file corrupted or unreadable: ${error instanceof Error ? error.message : 'Unknown error'}`,
          suggestion: 'Check memory file permissions and format. Restore from latest backup.',
          evidence: error
        }],
        score: 0
      };
    }
  }

  private createMemoryState(data: any, sourcePath: string): MemoryState {
    const jsonString = JSON.stringify(data, null, 2);
    const hash = crypto.createHash(this.config.hashAlgorithm).update(jsonString).digest('hex');
    
    return {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      hash,
      data: data,
      metadata: {
        version: '1.0.0',
        size: jsonString.length,
        checksumAlgorithm: this.config.hashAlgorithm
      }
    };
  }

  private validateMemoryStructure(data: any): Array<{
    type: 'corruption';
    severity: 'high' | 'critical';
    message: string;
    suggestion: string;
    evidence?: any;
  }> {
    const issues: Array<{
      type: 'corruption';
      severity: 'high' | 'critical';
      message: string;
      suggestion: string;
      evidence?: any;
    }> = [];

    if (!data || typeof data !== 'object') {
      issues.push({
        type: 'corruption',
        severity: 'critical',
        message: 'Memory data is not a valid object',
        suggestion: 'Check memory file format and content',
        evidence: typeof data
      });
    }

    // Check for circular references that might indicate tampering
    const seen = new WeakSet();
    const checkCircular = (obj: any, path: string = ''): void => {
      if (obj && typeof obj === 'object') {
        if (seen.has(obj)) {
          issues.push({
            type: 'corruption',
            severity: 'high',
            message: `Circular reference detected in memory at path: ${path}`,
            suggestion: 'Remove circular references to prevent memory corruption',
            evidence: path
          });
          return;
        }
        seen.add(obj);
        
        for (const [key, value] of Object.entries(obj)) {
          if (typeof value === 'object' && value !== null) {
            checkCircular(value, `${path}.${key}`);
          }
        }
      }
    };

    checkCircular(data);

    // Check for suspiciously large memory structures
    const size = JSON.stringify(data).length;
    if (size > 10 * 1024 * 1024) { // 10MB
      issues.push({
        type: 'corruption',
        severity: 'high',
        message: 'Memory size is unusually large (10MB+)',
        suggestion: 'Check for data duplication or memory leaks',
        evidence: { size, formatted: this.formatBytes(size) }
      });
    }

    return issues;
  }

  private detectAnomalies(currentState: MemoryState, previousState: MemoryState): Array<{
    type: 'anomaly';
    severity: 'low' | 'medium' | 'high';
    message: string;
    suggestion: string;
    evidence?: any;
  }> {
    const issues: Array<{
      type: 'anomaly';
      severity: 'low' | 'medium' | 'high';
      message: string;
      suggestion: string;
      evidence?: any;
    }> = [];

    const dataChange = this.calculateDataChange(currentState.data, previousState.data);
    
    if (dataChange > this.config.anomalyThreshold) {
      const severity: any = dataChange > 0.8 ? 'critical' : dataChange > 0.5 ? 'high' : 'medium';
      
      issues.push({
        type: 'anomaly',
        severity,
        message: `Significant memory change detected: ${(dataChange * 100).toFixed(1)}%`,
        suggestion: 'Verify this change is legitimate. Consider restoring from backup.',
        evidence: {
          changePercentage: dataChange,
          currentSize: currentState.metadata.size,
          previousSize: previousState.metadata.size,
          timestampDiff: currentState.timestamp - previousState.timestamp
        }
      });
    }

    // Check for suspicious timestamp patterns
    const timeDiff = currentState.timestamp - previousState.timestamp;
    if (timeDiff < 1000) { // Less than 1 second between states
      issues.push({
        type: 'anomaly',
        severity: 'medium' as any,
        message: 'Multiple memory states in very quick succession',
        suggestion: 'Check for rapid state changes that might indicate automation attacks',
        evidence: { timeDiff: `${timeDiff}ms` }
      });
    }

    return issues;
  }

  private detectInjectionAttempts(data: any): Array<{
    type: 'injection';
    severity: 'high' | 'critical';
    message: string;
    suggestion: string;
    evidence?: any;
  }> {
    const issues: Array<{
      type: 'injection';
      severity: 'high' | 'critical';
      message: string;
      suggestion: string;
      evidence?: any;
    }> = [];

    const searchForInjection = (obj: any, path: string = ''): void => {
      if (!obj || typeof obj !== 'object') return;

      for (const [key, value] of Object.entries(obj)) {
        const currentPath = path ? `${path}.${key}` : key;

        // Check for suspicious key patterns
        const suspiciousKeys = [
          'prompt', 'system_prompt', 'user_prompt',
          'instruction', 'command', 'directive',
          'override', 'bypass', 'ignore',
          'delete', 'remove', 'modify'
        ];

        if (suspiciousKeys.some(suspect => key.toLowerCase().includes(suspect))) {
          issues.push({
            type: 'injection',
            severity: 'high',
            message: `Suspicious memory key detected: ${key}`,
            suggestion: 'Review this key for potential injection attempts',
            evidence: { key, path: currentPath, value: typeof value }
          });
        }

        // Check for sensitive data in unexpected places
        if (typeof value === 'string') {
          for (const pattern of this.config.sensitivePatterns) {
            if (pattern.test(value)) {
              issues.push({
                type: 'injection',
                severity: 'critical',
                message: `Sensitive data pattern detected in memory: ${value.substring(0, 20)}...`,
                suggestion: 'Review this data for potential injection or unauthorized access',
                evidence: { pattern: pattern.toString(), path: currentPath, maskedValue: value.substring(0, 10) + '***' }
              });
            }
          }
        }

        // Recursively search nested objects
        if (typeof value === 'object' && value !== null) {
          searchForInjection(value, currentPath);
        }
      }
    };

    searchForInjection(data);

    return issues;
  }

  private async detectTampering(currentState: MemoryState, sourcePath: string): Promise<Array<{
    type: 'tampering';
    severity: 'critical';
    message: string;
    suggestion: string;
    evidence?: any;
  }>> {
    const issues: Array<{
      type: 'tampering';
      severity: 'critical';
      message: string;
      suggestion: string;
      evidence?: any;
    }> = [];

    // Verify file hasn't been modified since reading
    try {
      const stats = await fs.stat(sourcePath);
      if (currentState.timestamp > stats.mtime.getTime()) {
        issues.push({
          type: 'tampering',
          severity: 'critical',
          message: 'Memory file modified during validation process',
          suggestion: 'Immediate investigation required. File may be under active attack',
          evidence: {
            validationTime: currentState.timestamp,
            fileModifyTime: stats.mtime.getTime(),
            path: sourcePath
          }
        });
      }
    } catch (error) {
      issues.push({
        type: 'tampering',
        severity: 'critical',
        message: 'Unable to verify file integrity',
        suggestion: 'Check file system integrity and permissions',
        evidence: error
      });
    }

    return issues;
  }

  private calculateDataChange(current: any, previous: any): number {
    const currentStr = JSON.stringify(current, Object.keys(current).sort());
    const previousStr = JSON.stringify(previous, Object.keys(previous).sort());
    
    if (currentStr === previousStr) return 0;
    
    // Simple edit distance calculation for change percentage
    const maxLength = Math.max(currentStr.length, previousStr.length);
    const diff = this.calculateLevenshteinDistance(currentStr, previousStr);
    
    return diff / maxLength;
  }

  private calculateLevenshteinDistance(str1: string, str2: string): number {
    const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));

    for (let i = 0; i <= str1.length; i += 1) matrix[0][i] = i;
    for (let j = 0; j <= str2.length; j += 1) matrix[j][0] = j;

    for (let j = 1; j <= str2.length; j += 1) {
      for (let i = 1; i <= str1.length; i += 1) {
        const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[j][i] = Math.min(
          matrix[j][i - 1] + 1, // deletion
          matrix[j - 1][i] + 1, // insertion
          matrix[j - 1][i - 1] + indicator, // substitution
        );
      }
    }

    return matrix[str2.length][str1.length];
  }

  private calculateSecurityScore(issues: Array<{ severity: string }>): number {
    if (issues.length === 0) return 100;

    const severityWeights = {
      low: 1,
      medium: 3,
      high: 5,
      critical: 10
    };

    const totalWeight = issues.reduce((sum, issue) => 
      sum + (severityWeights[issue.severity as keyof typeof severityWeights] || 1), 0
    );

    // Max score reduction based on critical issues
    const maxReduction = Math.min(100, totalWeight * 10);
    return Math.max(0, 100 - maxReduction);
  }

  private formatBytes(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }

  async backupMemory(memoryPath: string, state: MemoryState): Promise<string> {
    await fs.mkdir(this.config.backupDirectory, { recursive: true });
    
    const backupPath = path.join(
      this.config.backupDirectory,
      `memory-backup-${state.timestamp}-${state.id}.json`
    );

    await fs.writeFile(backupPath, JSON.stringify(state, null, 2));
    
    // Clean old backups
    await this.cleanOldBackups();
    
    return backupPath;
  }

  private async cleanOldBackups(): Promise<void> {
    try {
      const files = await fs.readdir(this.config.backupDirectory);
      const backupFiles = files
        .filter(file => file.startsWith('memory-backup-') && file.endsWith('.json'))
        .map(file => ({
          name: file,
          path: path.join(this.config.backupDirectory, file),
          stats: fs.stat(path.join(this.config.backupDirectory, file))
        }));

      const sortedBackups = (await Promise.all(backupFiles.map(async f => ({
        ...f,
          mtime: (await f.stats).mtime
      })))).sort((a, b) => b.mtime.getTime() - a.mtime.getTime());

      const toDelete = sortedBackups.slice(this.config.maxBackups);
      await Promise.all(toDelete.map(file => fs.unlink(file.path)));
    } catch (error) {
      // Ignore cleanup errors
      console.warn('Warning: Failed to clean old backups:', error);
    }
  }

  async restoreFromBackup(memoryPath: string, timestamp?: number): Promise<string> {
    const backups = await this.getAvailableBackups();
    
    if (backups.length === 0) {
      throw new Error('No available backups found');
    }

    const targetBackup = timestamp ?
      backups.find(backup => backup.timestamp === timestamp) :
      backups[0]; // Latest backup

    if (!targetBackup) {
      throw new Error(`Backup not found for timestamp: ${timestamp}`);
    }

    const backupData = await fs.readFile(targetBackup.path, 'utf-8');
    const state = JSON.parse(backupData);
    
    await fs.writeFile(memoryPath, JSON.stringify(state.data, null, 2));
    
    return targetBackup.path;
  }

  private async getAvailableBackups(): Promise<Array<{
    path: string;
    timestamp: number;
    id: string;
    mtime: Date;
  }>> {
    try {
      const files = await fs.readdir(this.config.backupDirectory);
      const backupFiles = files
        .filter(file => file.startsWith('memory-backup-') && file.endsWith('.json'))
        .map(async file => {
          const filePath = path.join(this.config.backupDirectory, file);
          const stats = await fs.stat(filePath);
          const data = JSON.parse(await fs.readFile(filePath, 'utf-8'));
          
          return {
            path: filePath,
            timestamp: data.timestamp,
            id: data.id,
            mtime: stats.mtime
          };
        });

      return (await Promise.all(backupFiles))
        .sort((a, b) => b.mtime.getTime() - a.mtime.getTime());
    } catch (error) {
      return [];
    }
  }
}