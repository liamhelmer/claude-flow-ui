# Claude Flow UI - Plugin Development Guide

## Table of Contents

1. [Overview](#overview)
2. [Transformation System Architecture](#transformation-system-architecture)
3. [Creating Custom Transformations](#creating-custom-transformations)
4. [Plugin Registration and Discovery](#plugin-registration-and-discovery)
5. [Advanced Plugin Features](#advanced-plugin-features)
6. [Testing and Validation](#testing-and-validation)
7. [Distribution and Packaging](#distribution-and-packaging)
8. [Best Practices](#best-practices)
9. [Examples and Templates](#examples-and-templates)
10. [API Reference](#api-reference)

## Overview

Claude Flow UI provides a powerful transformation system that allows developers to create custom plugins for data processing, terminal enhancements, and workflow automation. This guide covers how to develop, test, and distribute custom transformations.

### Plugin Types

1. **Data Transformations**: Process and transform data streams
2. **Terminal Enhancements**: Extend terminal functionality
3. **Workflow Plugins**: Automate common tasks
4. **Integration Plugins**: Connect with external services

### Architecture Overview

```
Plugin System
├── BaseTransformation (Abstract Class)
├── TransformationChain (Composition)
├── TransformationManager (Registration)
└── Plugin Runtime (Execution)
```

## Transformation System Architecture

### Core Components

#### BaseTransformation Interface

```typescript
interface BaseTransformation<TInput = any, TOutput = any> {
  readonly name: string;
  readonly version: string;
  readonly description: string;

  configure(config: Partial<TransformationConfig>): this;
  chain<TNext>(next: BaseTransformation<TOutput, TNext>): ChainedTransformation<TInput, TNext>;
  transform(data: TInput, context: TransformationContext, onProgress?: ProgressCallback): Promise<TransformationResult<TOutput>>;
  validate(data: TInput): Promise<TransformationError[]>;
}
```

#### Core Types

```typescript
interface TransformationConfig {
  batchSize: number;
  parallel: boolean;
  maxRetries: number;
  timeout: number;
  preserveOriginal: boolean;
}

interface TransformationContext {
  id: string;
  startTime: Date;
  metadata: Record<string, any>;
  config: TransformationConfig;
}

interface TransformationResult<T> {
  success: boolean;
  data: T;
  errors: TransformationError[];
  warnings: string[];
  metadata: {
    processed: number;
    skipped: number;
    failed: number;
    duration: number;
  };
}

interface TransformationError {
  code: string;
  message: string;
  severity: 'error' | 'warning' | 'info';
}
```

## Creating Custom Transformations

### Basic Transformation Template

```typescript
// src/transformations/MyCustomTransformation.ts
import { AbstractTransformation, TransformationContext, TransformationResult } from './BaseTransformation';

export class MyCustomTransformation extends AbstractTransformation<InputType, OutputType> {
  readonly name = 'my-custom-transformation';
  readonly version = '1.0.0';
  readonly description = 'A custom transformation for processing data';

  async transform(
    data: InputType,
    context: TransformationContext,
    onProgress?: ProgressCallback
  ): Promise<TransformationResult<OutputType>> {
    const startTime = new Date();

    try {
      // Validation
      const validationErrors = await this.validate(data);
      if (validationErrors.length > 0) {
        return {
          success: false,
          data: null as OutputType,
          errors: validationErrors,
          warnings: [],
          metadata: {
            processed: 0,
            skipped: 0,
            failed: 1,
            duration: Date.now() - startTime.getTime()
          }
        };
      }

      // Progress reporting
      if (onProgress) {
        onProgress({
          taskId: context.id,
          total: 1,
          processed: 0,
          failed: 0,
          percentage: 0,
          currentOperation: 'Starting transformation'
        });
      }

      // Your transformation logic here
      const processedData = await this.processData(data, context, onProgress);

      // Success result
      return this.createSuccessResult(
        processedData,
        1, // processed count
        0, // skipped count
        0, // failed count
        [], // errors
        [], // warnings
        startTime
      );

    } catch (error) {
      return {
        success: false,
        data: null as OutputType,
        errors: [{
          code: 'PROCESSING_ERROR',
          message: error instanceof Error ? error.message : 'Unknown error',
          severity: 'error'
        }],
        warnings: [],
        metadata: {
          processed: 0,
          skipped: 0,
          failed: 1,
          duration: Date.now() - startTime.getTime()
        }
      };
    }
  }

  async validate(data: InputType): Promise<TransformationError[]> {
    const errors: TransformationError[] = [];

    // Add your validation logic here
    if (!data) {
      errors.push({
        code: 'INVALID_INPUT',
        message: 'Input data is required',
        severity: 'error'
      });
    }

    // Type-specific validation
    if (typeof data !== 'object') {
      errors.push({
        code: 'TYPE_ERROR',
        message: 'Input must be an object',
        severity: 'error'
      });
    }

    return errors;
  }

  private async processData(
    data: InputType,
    context: TransformationContext,
    onProgress?: ProgressCallback
  ): Promise<OutputType> {
    // Implement your core transformation logic
    // Use this.config for configuration options
    // Report progress using onProgress callback

    return processedData;
  }
}
```

### Advanced Transformation Example

```typescript
// src/transformations/DataProcessorTransformation.ts
export class DataProcessorTransformation extends AbstractTransformation<any[], ProcessedData[]> {
  readonly name = 'data-processor';
  readonly version = '2.1.0';
  readonly description = 'Processes arrays of data with filtering and transformation';

  // Custom configuration schema
  private readonly configSchema = {
    filterCriteria: { type: 'object', default: {} },
    transformRules: { type: 'array', default: [] },
    outputFormat: { type: 'string', enum: ['json', 'csv', 'xml'], default: 'json' }
  };

  async transform(
    data: any[],
    context: TransformationContext,
    onProgress?: ProgressCallback
  ): Promise<TransformationResult<ProcessedData[]>> {
    const startTime = new Date();

    // Use batch processing for large datasets
    const { results, errors } = await this.processBatch(
      data,
      (item, index) => this.processItem(item, index, context),
      context,
      onProgress
    );

    return this.createSuccessResult(
      results,
      results.length,
      0,
      errors.length,
      errors,
      this.generateWarnings(results),
      startTime
    );
  }

  private async processItem(item: any, index: number, context: TransformationContext): Promise<ProcessedData> {
    // Apply transformation rules
    let processedItem = { ...item };

    // Custom processing logic
    const rules = this.config.transformRules || [];
    for (const rule of rules) {
      processedItem = await this.applyRule(processedItem, rule);
    }

    return {
      id: index,
      originalData: this.config.preserveOriginal ? item : undefined,
      transformedData: processedItem,
      processedAt: new Date().toISOString(),
      metadata: {
        rulesApplied: rules.length,
        transformationContext: context.id
      }
    };
  }

  private async applyRule(data: any, rule: TransformationRule): Promise<any> {
    switch (rule.type) {
      case 'filter':
        return this.applyFilter(data, rule.criteria);
      case 'transform':
        return this.applyTransform(data, rule.transformer);
      case 'enrich':
        return this.enrichData(data, rule.enrichment);
      default:
        return data;
    }
  }

  async validate(data: any[]): Promise<TransformationError[]> {
    const errors: TransformationError[] = [];

    if (!Array.isArray(data)) {
      errors.push({
        code: 'INVALID_TYPE',
        message: 'Input must be an array',
        severity: 'error'
      });
    }

    if (data.length === 0) {
      errors.push({
        code: 'EMPTY_INPUT',
        message: 'Input array is empty',
        severity: 'warning'
      });
    }

    // Validate configuration
    const configErrors = this.validateConfiguration();
    errors.push(...configErrors);

    return errors;
  }

  private validateConfiguration(): TransformationError[] {
    const errors: TransformationError[] = [];

    // Validate custom configuration
    const config = this.config as any;

    if (config.transformRules && !Array.isArray(config.transformRules)) {
      errors.push({
        code: 'INVALID_CONFIG',
        message: 'transformRules must be an array',
        severity: 'error'
      });
    }

    if (config.outputFormat && !['json', 'csv', 'xml'].includes(config.outputFormat)) {
      errors.push({
        code: 'INVALID_OUTPUT_FORMAT',
        message: 'outputFormat must be json, csv, or xml',
        severity: 'error'
      });
    }

    return errors;
  }

  private generateWarnings(results: ProcessedData[]): string[] {
    const warnings: string[] = [];

    // Generate contextual warnings
    const failedCount = results.filter(r => !r.transformedData).length;
    if (failedCount > 0) {
      warnings.push(`${failedCount} items failed to process`);
    }

    const emptyCount = results.filter(r => !r.transformedData || Object.keys(r.transformedData).length === 0).length;
    if (emptyCount > 0) {
      warnings.push(`${emptyCount} items resulted in empty data`);
    }

    return warnings;
  }
}
```

## Plugin Registration and Discovery

### Plugin Manager

```typescript
// src/transformations/PluginManager.ts
export class PluginManager {
  private transformations = new Map<string, BaseTransformation>();
  private pluginMetadata = new Map<string, PluginMetadata>();

  register(transformation: BaseTransformation, metadata?: PluginMetadata): void {
    const name = transformation.name;

    // Validate transformation
    this.validateTransformation(transformation);

    // Register transformation
    this.transformations.set(name, transformation);

    // Store metadata
    if (metadata) {
      this.pluginMetadata.set(name, metadata);
    }

    console.log(`✅ Registered transformation: ${name} v${transformation.version}`);
  }

  unregister(name: string): boolean {
    const removed = this.transformations.delete(name);
    this.pluginMetadata.delete(name);

    if (removed) {
      console.log(`🗑️ Unregistered transformation: ${name}`);
    }

    return removed;
  }

  get(name: string): BaseTransformation | undefined {
    return this.transformations.get(name);
  }

  list(): TransformationInfo[] {
    return Array.from(this.transformations.entries()).map(([name, transformation]) => ({
      name,
      version: transformation.version,
      description: transformation.description,
      metadata: this.pluginMetadata.get(name)
    }));
  }

  async loadPlugin(pluginPath: string): Promise<void> {
    try {
      const pluginModule = await import(pluginPath);

      // Support multiple export formats
      const TransformationClass = pluginModule.default || pluginModule[Object.keys(pluginModule)[0]];

      if (typeof TransformationClass === 'function') {
        const instance = new TransformationClass();
        this.register(instance, pluginModule.metadata);
      } else {
        throw new Error('Plugin must export a transformation class');
      }
    } catch (error) {
      console.error(`Failed to load plugin from ${pluginPath}:`, error);
      throw error;
    }
  }

  private validateTransformation(transformation: BaseTransformation): void {
    if (!transformation.name || typeof transformation.name !== 'string') {
      throw new Error('Transformation must have a string name');
    }

    if (!transformation.version || typeof transformation.version !== 'string') {
      throw new Error('Transformation must have a version string');
    }

    if (typeof transformation.transform !== 'function') {
      throw new Error('Transformation must implement transform method');
    }

    if (typeof transformation.validate !== 'function') {
      throw new Error('Transformation must implement validate method');
    }

    if (this.transformations.has(transformation.name)) {
      throw new Error(`Transformation ${transformation.name} is already registered`);
    }
  }
}
```

### Auto-Discovery System

```typescript
// src/transformations/PluginDiscovery.ts
export class PluginDiscovery {
  private pluginManager: PluginManager;
  private pluginDirectories: string[] = [
    path.join(process.cwd(), 'src/transformations/plugins'),
    path.join(process.cwd(), 'plugins'),
    path.join(os.homedir(), '.claude-flow-ui/plugins')
  ];

  constructor(pluginManager: PluginManager) {
    this.pluginManager = pluginManager;
  }

  async discoverPlugins(): Promise<void> {
    console.log('🔍 Discovering plugins...');

    for (const directory of this.pluginDirectories) {
      if (fs.existsSync(directory)) {
        await this.scanDirectory(directory);
      }
    }
  }

  private async scanDirectory(directory: string): Promise<void> {
    try {
      const entries = fs.readdirSync(directory, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(directory, entry.name);

        if (entry.isDirectory()) {
          // Check for package.json indicating a plugin package
          const packageJsonPath = path.join(fullPath, 'package.json');
          if (fs.existsSync(packageJsonPath)) {
            await this.loadPluginPackage(fullPath);
          }
        } else if (entry.name.endsWith('.js') || entry.name.endsWith('.ts')) {
          // Load individual plugin files
          await this.pluginManager.loadPlugin(fullPath);
        }
      }
    } catch (error) {
      console.error(`Error scanning plugin directory ${directory}:`, error);
    }
  }

  private async loadPluginPackage(packagePath: string): Promise<void> {
    try {
      const packageJson = JSON.parse(
        fs.readFileSync(path.join(packagePath, 'package.json'), 'utf8')
      );

      // Check if it's a Claude Flow UI plugin
      if (packageJson.keywords?.includes('claude-flow-ui-plugin')) {
        const entryPoint = packageJson.main || 'index.js';
        const pluginPath = path.join(packagePath, entryPoint);

        if (fs.existsSync(pluginPath)) {
          await this.pluginManager.loadPlugin(pluginPath);
        }
      }
    } catch (error) {
      console.error(`Error loading plugin package ${packagePath}:`, error);
    }
  }

  addPluginDirectory(directory: string): void {
    if (!this.pluginDirectories.includes(directory)) {
      this.pluginDirectories.push(directory);
    }
  }
}
```

## Advanced Plugin Features

### Plugin Configuration Schema

```typescript
// src/transformations/ConfigurationSchema.ts
export interface PluginConfigSchema {
  properties: Record<string, SchemaProperty>;
  required?: string[];
  additionalProperties?: boolean;
}

interface SchemaProperty {
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description?: string;
  default?: any;
  enum?: any[];
  minimum?: number;
  maximum?: number;
  pattern?: string;
  items?: SchemaProperty;
  properties?: Record<string, SchemaProperty>;
}

export class ConfigurableTransformation extends AbstractTransformation {
  protected schema: PluginConfigSchema = {
    properties: {},
    required: [],
    additionalProperties: true
  };

  getConfigurationSchema(): PluginConfigSchema {
    return this.schema;
  }

  validateConfiguration(config: any): TransformationError[] {
    const errors: TransformationError[] = [];

    // Validate required properties
    for (const required of this.schema.required || []) {
      if (!(required in config)) {
        errors.push({
          code: 'MISSING_REQUIRED_PROPERTY',
          message: `Required property '${required}' is missing`,
          severity: 'error'
        });
      }
    }

    // Validate property types and constraints
    for (const [property, definition] of Object.entries(this.schema.properties)) {
      if (property in config) {
        const value = config[property];
        const propertyErrors = this.validateProperty(property, value, definition);
        errors.push(...propertyErrors);
      }
    }

    return errors;
  }

  private validateProperty(
    name: string,
    value: any,
    definition: SchemaProperty
  ): TransformationError[] {
    const errors: TransformationError[] = [];

    // Type validation
    if (!this.isValidType(value, definition.type)) {
      errors.push({
        code: 'INVALID_TYPE',
        message: `Property '${name}' must be of type ${definition.type}`,
        severity: 'error'
      });
      return errors; // Skip further validation if type is wrong
    }

    // Enum validation
    if (definition.enum && !definition.enum.includes(value)) {
      errors.push({
        code: 'INVALID_ENUM_VALUE',
        message: `Property '${name}' must be one of: ${definition.enum.join(', ')}`,
        severity: 'error'
      });
    }

    // Number constraints
    if (definition.type === 'number') {
      if (definition.minimum !== undefined && value < definition.minimum) {
        errors.push({
          code: 'VALUE_TOO_SMALL',
          message: `Property '${name}' must be >= ${definition.minimum}`,
          severity: 'error'
        });
      }

      if (definition.maximum !== undefined && value > definition.maximum) {
        errors.push({
          code: 'VALUE_TOO_LARGE',
          message: `Property '${name}' must be <= ${definition.maximum}`,
          severity: 'error'
        });
      }
    }

    // String pattern validation
    if (definition.type === 'string' && definition.pattern) {
      const regex = new RegExp(definition.pattern);
      if (!regex.test(value)) {
        errors.push({
          code: 'INVALID_PATTERN',
          message: `Property '${name}' does not match required pattern`,
          severity: 'error'
        });
      }
    }

    return errors;
  }

  private isValidType(value: any, expectedType: string): boolean {
    switch (expectedType) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return typeof value === 'number' && !isNaN(value);
      case 'boolean':
        return typeof value === 'boolean';
      case 'object':
        return typeof value === 'object' && value !== null && !Array.isArray(value);
      case 'array':
        return Array.isArray(value);
      default:
        return false;
    }
  }
}
```

### Async and Streaming Support

```typescript
// src/transformations/StreamingTransformation.ts
export abstract class StreamingTransformation<TInput, TOutput> extends AbstractTransformation<TInput, TOutput> {
  async *transformStream(
    inputStream: AsyncIterable<TInput>,
    context: TransformationContext,
    onProgress?: ProgressCallback
  ): AsyncGenerator<TOutput, void, unknown> {
    let processed = 0;
    let failed = 0;

    for await (const item of inputStream) {
      try {
        const result = await this.transformItem(item, context);

        if (result) {
          yield result;
          processed++;
        }

        if (onProgress) {
          onProgress({
            taskId: context.id,
            total: -1, // Unknown total for streams
            processed,
            failed,
            percentage: -1,
            currentOperation: `Processing item ${processed + 1}`
          });
        }
      } catch (error) {
        failed++;
        console.error(`Error processing item ${processed + 1}:`, error);

        // Optionally yield error or skip
        if (this.config.continueOnError) {
          continue;
        } else {
          throw error;
        }
      }
    }
  }

  protected abstract transformItem(item: TInput, context: TransformationContext): Promise<TOutput | null>;

  // Override the main transform method to use streaming
  async transform(
    data: TInput,
    context: TransformationContext,
    onProgress?: ProgressCallback
  ): Promise<TransformationResult<TOutput>> {
    // Convert single item to stream
    const inputStream = this.createInputStream(data);
    const results: TOutput[] = [];

    for await (const result of this.transformStream(inputStream, context, onProgress)) {
      results.push(result);
    }

    return this.createSuccessResult(
      results as any, // Type assertion for compatibility
      results.length,
      0,
      0,
      [],
      [],
      context.startTime
    );
  }

  private async *createInputStream(data: TInput): AsyncIterable<TInput> {
    if (Array.isArray(data)) {
      for (const item of data) {
        yield item;
      }
    } else {
      yield data;
    }
  }
}
```

## Testing and Validation

### Plugin Testing Framework

```typescript
// src/transformations/testing/PluginTester.ts
export class PluginTester {
  static async testTransformation<TInput, TOutput>(
    transformation: BaseTransformation<TInput, TOutput>,
    testCases: TestCase<TInput, TOutput>[]
  ): Promise<TestResults> {
    const results: TestResults = {
      passed: 0,
      failed: 0,
      total: testCases.length,
      details: []
    };

    for (const testCase of testCases) {
      const testResult = await this.runTestCase(transformation, testCase);
      results.details.push(testResult);

      if (testResult.passed) {
        results.passed++;
      } else {
        results.failed++;
      }
    }

    return results;
  }

  private static async runTestCase<TInput, TOutput>(
    transformation: BaseTransformation<TInput, TOutput>,
    testCase: TestCase<TInput, TOutput>
  ): Promise<TestCaseResult> {
    const startTime = Date.now();

    try {
      // Setup configuration if provided
      if (testCase.config) {
        transformation.configure(testCase.config);
      }

      // Create test context
      const context = {
        id: `test_${Date.now()}`,
        startTime: new Date(),
        metadata: {},
        config: transformation['config'] || {}
      };

      // Run transformation
      const result = await transformation.transform(testCase.input, context);

      // Validate result
      const validationErrors = this.validateResult(result, testCase.expected);

      return {
        name: testCase.name,
        passed: validationErrors.length === 0,
        errors: validationErrors,
        duration: Date.now() - startTime,
        result: result
      };
    } catch (error) {
      return {
        name: testCase.name,
        passed: false,
        errors: [`Unexpected error: ${error.message}`],
        duration: Date.now() - startTime,
        result: null
      };
    }
  }

  private static validateResult<TOutput>(
    actual: TransformationResult<TOutput>,
    expected: Partial<TransformationResult<TOutput>>
  ): string[] {
    const errors: string[] = [];

    // Validate success state
    if (expected.success !== undefined && actual.success !== expected.success) {
      errors.push(`Expected success: ${expected.success}, got: ${actual.success}`);
    }

    // Validate data (deep comparison)
    if (expected.data !== undefined) {
      if (!this.deepEqual(actual.data, expected.data)) {
        errors.push(`Data mismatch. Expected: ${JSON.stringify(expected.data)}, got: ${JSON.stringify(actual.data)}`);
      }
    }

    // Validate error count
    if (expected.errors !== undefined) {
      if (actual.errors.length !== expected.errors.length) {
        errors.push(`Expected ${expected.errors.length} errors, got ${actual.errors.length}`);
      }
    }

    return errors;
  }

  private static deepEqual(a: any, b: any): boolean {
    return JSON.stringify(a) === JSON.stringify(b);
  }
}

// Test case interfaces
interface TestCase<TInput, TOutput> {
  name: string;
  input: TInput;
  expected: Partial<TransformationResult<TOutput>>;
  config?: Partial<TransformationConfig>;
}

interface TestCaseResult {
  name: string;
  passed: boolean;
  errors: string[];
  duration: number;
  result: TransformationResult<any> | null;
}

interface TestResults {
  passed: number;
  failed: number;
  total: number;
  details: TestCaseResult[];
}
```

### Example Test Suite

```typescript
// tests/transformations/MyCustomTransformation.test.ts
describe('MyCustomTransformation', () => {
  let transformation: MyCustomTransformation;

  beforeEach(() => {
    transformation = new MyCustomTransformation();
  });

  const testCases: TestCase<InputType, OutputType>[] = [
    {
      name: 'should transform valid input',
      input: { value: 'test' },
      expected: {
        success: true,
        data: { processedValue: 'TEST' }
      }
    },
    {
      name: 'should handle empty input',
      input: {},
      expected: {
        success: false,
        errors: [
          expect.objectContaining({
            code: 'INVALID_INPUT',
            severity: 'error'
          })
        ]
      }
    },
    {
      name: 'should respect configuration',
      input: { value: 'test' },
      config: { preserveOriginal: true },
      expected: {
        success: true,
        data: expect.objectContaining({
          original: { value: 'test' }
        })
      }
    }
  ];

  it('should pass all test cases', async () => {
    const results = await PluginTester.testTransformation(transformation, testCases);

    expect(results.failed).toBe(0);
    expect(results.passed).toBe(testCases.length);
  });

  it('should validate input correctly', async () => {
    const errors = await transformation.validate(null);
    expect(errors).toHaveLength(1);
    expect(errors[0].code).toBe('INVALID_INPUT');
  });

  it('should chain with other transformations', () => {
    const secondTransformation = new AnotherTransformation();
    const chain = transformation.chain(secondTransformation);

    expect(chain).toBeInstanceOf(TransformationChain);
    expect(chain.transformations).toHaveLength(2);
  });
});
```

## Distribution and Packaging

### Plugin Package Structure

```
my-claude-flow-plugin/
├── package.json
├── README.md
├── src/
│   ├── index.ts
│   ├── transformations/
│   │   └── MyTransformation.ts
│   └── types/
│       └── index.ts
├── tests/
│   └── MyTransformation.test.ts
├── examples/
│   └── usage-example.js
└── docs/
    └── API.md
```

### Package.json Example

```json
{
  "name": "claude-flow-ui-my-plugin",
  "version": "1.0.0",
  "description": "Custom transformation plugin for Claude Flow UI",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "keywords": [
    "claude-flow-ui-plugin",
    "transformation",
    "data-processing"
  ],
  "author": "Your Name <your.email@example.com>",
  "license": "MIT",
  "engines": {
    "node": ">=18.0.0"
  },
  "peerDependencies": {
    "@liamhelmer/claude-flow-ui": "^1.2.0"
  },
  "devDependencies": {
    "@types/node": "^18.0.0",
    "typescript": "^5.0.0",
    "jest": "^29.0.0"
  },
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "prepublishOnly": "npm run build"
  },
  "files": [
    "dist/",
    "README.md"
  ],
  "claudeFlowUI": {
    "pluginVersion": "1.0",
    "compatibleVersions": ["^1.2.0"],
    "transformations": [
      {
        "name": "my-transformation",
        "class": "MyTransformation",
        "description": "Custom data transformation"
      }
    ]
  }
}
```

### Plugin Entry Point

```typescript
// src/index.ts
export { MyTransformation } from './transformations/MyTransformation';
export { MyStreamingTransformation } from './transformations/MyStreamingTransformation';

// Plugin metadata
export const metadata = {
  name: 'my-claude-flow-plugin',
  version: '1.0.0',
  description: 'Custom transformation plugin',
  author: 'Your Name',
  transformations: [
    {
      name: 'my-transformation',
      class: 'MyTransformation'
    },
    {
      name: 'my-streaming-transformation',
      class: 'MyStreamingTransformation'
    }
  ]
};

// Default export for convenience
import { MyTransformation } from './transformations/MyTransformation';
export default MyTransformation;
```

## Best Practices

### Development Best Practices

1. **Follow TypeScript Guidelines**
```typescript
// Use strict typing
interface ProcessedData {
  id: string;
  data: any;
  metadata: {
    processedAt: string;
    version: string;
  };
}

// Provide comprehensive JSDoc comments
/**
 * Transforms input data according to specified rules
 * @param data - The input data to transform
 * @param context - Transformation execution context
 * @param onProgress - Optional progress callback
 * @returns Promise resolving to transformation result
 */
async transform(data: InputType, context: TransformationContext, onProgress?: ProgressCallback): Promise<TransformationResult<OutputType>> {
  // Implementation
}
```

2. **Error Handling**
```typescript
// Comprehensive error handling
try {
  const result = await this.processData(data);
  return this.createSuccessResult(result);
} catch (error) {
  // Log error for debugging
  console.error('Transformation failed:', error);

  // Return structured error result
  return {
    success: false,
    data: null,
    errors: [{
      code: this.getErrorCode(error),
      message: error.message,
      severity: 'error'
    }],
    warnings: [],
    metadata: { /* ... */ }
  };
}

private getErrorCode(error: Error): string {
  if (error instanceof ValidationError) return 'VALIDATION_ERROR';
  if (error instanceof NetworkError) return 'NETWORK_ERROR';
  return 'UNKNOWN_ERROR';
}
```

3. **Configuration Management**
```typescript
// Validate configuration on change
configure(config: Partial<TransformationConfig>): this {
  const mergedConfig = { ...this.config, ...config };

  // Validate configuration
  const errors = this.validateConfiguration(mergedConfig);
  if (errors.length > 0) {
    throw new Error(`Invalid configuration: ${errors.map(e => e.message).join(', ')}`);
  }

  this.config = mergedConfig;
  return this;
}
```

4. **Performance Optimization**
```typescript
// Use batching for large datasets
private async processBatch<T>(
  items: T[],
  processor: (item: T) => Promise<any>,
  batchSize: number = 100
): Promise<any[]> {
  const results = [];

  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(processor));
    results.push(...batchResults);

    // Allow event loop to process other tasks
    await new Promise(resolve => setImmediate(resolve));
  }

  return results;
}
```

### Testing Best Practices

1. **Comprehensive Test Coverage**
```typescript
describe('MyTransformation', () => {
  // Test normal operation
  it('should transform valid data');

  // Test edge cases
  it('should handle empty input');
  it('should handle null/undefined input');
  it('should handle malformed data');

  // Test configuration
  it('should respect configuration options');
  it('should validate configuration');

  // Test error handling
  it('should handle processing errors gracefully');
  it('should provide meaningful error messages');

  // Test performance
  it('should complete within reasonable time', { timeout: 5000 });
});
```

2. **Mock External Dependencies**
```typescript
// Mock external services
jest.mock('../services/ExternalService', () => ({
  ExternalService: jest.fn().mockImplementation(() => ({
    process: jest.fn().mockResolvedValue({ result: 'mocked' })
  }))
}));
```

### Documentation Best Practices

1. **API Documentation**
```typescript
/**
 * Custom transformation for processing user data
 *
 * @example
 * ```typescript
 * const transformation = new MyTransformation();
 * transformation.configure({
 *   outputFormat: 'json',
 *   includeMetadata: true
 * });
 *
 * const result = await transformation.transform(inputData, context);
 * console.log(result.data);
 * ```
 */
export class MyTransformation extends AbstractTransformation {
  // Implementation
}
```

2. **README Template**
```markdown
# My Claude Flow UI Plugin

## Installation
npm install claude-flow-ui-my-plugin

## Usage
```javascript
const { MyTransformation } = require('claude-flow-ui-my-plugin');
// Usage examples
```

## Configuration
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| option1 | string | 'default' | Description |

## API Reference
[Link to detailed API docs]

## Examples
[Link to examples folder]

## Contributing
[Contribution guidelines]
```

## Examples and Templates

### Template Repository Structure

Create a GitHub template repository with:

```
claude-flow-ui-plugin-template/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   └── release.yml
│   └── ISSUE_TEMPLATE/
├── src/
│   ├── index.ts
│   ├── transformations/
│   │   └── ExampleTransformation.ts
│   └── types/
│       └── index.ts
├── tests/
│   └── ExampleTransformation.test.ts
├── docs/
│   └── API.md
├── examples/
│   └── basic-usage.js
├── package.json
├── tsconfig.json
├── jest.config.js
└── README.md
```

### CLI Plugin Generator

```bash
#!/bin/bash
# generate-plugin.sh

PLUGIN_NAME=$1
AUTHOR_NAME=${2:-"Unknown Author"}

if [ -z "$PLUGIN_NAME" ]; then
    echo "Usage: generate-plugin.sh <plugin-name> [author-name]"
    exit 1
fi

# Create plugin directory
mkdir "claude-flow-ui-$PLUGIN_NAME"
cd "claude-flow-ui-$PLUGIN_NAME"

# Generate package.json
cat > package.json << EOF
{
  "name": "claude-flow-ui-$PLUGIN_NAME",
  "version": "1.0.0",
  "description": "Custom transformation plugin for Claude Flow UI",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "keywords": ["claude-flow-ui-plugin", "transformation"],
  "author": "$AUTHOR_NAME",
  "license": "MIT"
}
EOF

# Generate basic transformation
mkdir -p src/transformations
cat > src/transformations/${PLUGIN_NAME^}Transformation.ts << EOF
import { AbstractTransformation, TransformationContext, TransformationResult } from '@liamhelmer/claude-flow-ui';

export class ${PLUGIN_NAME^}Transformation extends AbstractTransformation {
  readonly name = '$PLUGIN_NAME-transformation';
  readonly version = '1.0.0';
  readonly description = 'Custom $PLUGIN_NAME transformation';

  async transform(data: any, context: TransformationContext): Promise<TransformationResult<any>> {
    // TODO: Implement your transformation logic
    return this.createSuccessResult(data, 1, 0, 0);
  }

  async validate(data: any): Promise<TransformationError[]> {
    // TODO: Implement validation logic
    return [];
  }
}
EOF

echo "Plugin template created in claude-flow-ui-$PLUGIN_NAME/"
```

## API Reference

### Core Interfaces

[Complete API reference would include all interfaces, classes, and methods available for plugin development]

This plugin development guide provides everything needed to create, test, and distribute custom transformations for Claude Flow UI. The modular architecture allows for powerful extensions while maintaining system stability and performance.