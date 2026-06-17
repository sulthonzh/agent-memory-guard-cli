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
    score: number;
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
export declare class MemoryValidator {
    private config;
    constructor(config?: Partial<MemoryConfig>);
    validateMemoryState(memoryPath: string, previousState?: MemoryState): Promise<ValidationResult>;
    private createMemoryState;
    private validateMemoryStructure;
    private detectAnomalies;
    private detectInjectionAttempts;
    private detectTampering;
    private calculateDataChange;
    private calculateLevenshteinDistance;
    private calculateSecurityScore;
    private formatBytes;
    backupMemory(memoryPath: string, state: MemoryState): Promise<string>;
    private cleanOldBackups;
    restoreFromBackup(memoryPath: string, timestamp?: number): Promise<string>;
    private getAvailableBackups;
}
//# sourceMappingURL=memory-validator.d.ts.map