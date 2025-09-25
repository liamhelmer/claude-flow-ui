#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const { Transform } = require('stream');
const { createReadStream, createWriteStream } = require('fs');
const csv = require('csv-parser');
const xml2js = require('xml2js');

/**
 * Data Migration Tool - Batch Processing Example
 *
 * This example demonstrates batch processing for data format conversion:
 * - CSV to JSON conversion
 * - JSON to CSV conversion
 * - XML to JSON conversion
 * - Database export/import simulation
 * - Schema mapping and validation
 * - Data transformation pipelines
 * - Progress tracking and rollback
 */

class DataMigrator {
  constructor(config = {}) {
    this.config = {
      batchSize: 5000,
      outputDir: './migrated',
      backupDir: './backup',
      tempDir: './temp',
      formats: ['csv', 'json', 'xml', 'sql'],
      validation: {
        enabled: true,
        strictMode: false,
        skipErrors: true
      },
      transformation: {
        dateFormat: 'ISO', // ISO, US, EU
        numberFormat: 'US', // US, EU
        textEncoding: 'utf8',
        nullValues: ['', 'null', 'NULL', 'N/A', 'n/a']
      },
      performance: {
        memoryLimit: '512MB',
        concurrentFiles: 3,
        streamingThreshold: 100000
      },
      ...config
    };

    this.stats = {
      totalRecords: 0,
      converted: 0,
      errors: 0,
      skipped: 0,
      filesProcessed: 0,
      startTime: null,
      endTime: null,
      conversionMap: {}
    };

    this.schemas = new Map();
    this.validators = new Map();
    this.transformers = new Map();

    // Initialize built-in transformers
    this.initializeTransformers();
  }

  /**
   * Initialize data transformers
   */
  initializeTransformers() {
    // Date transformer
    this.transformers.set('date', (value) => {
      if (!value || this.config.transformation.nullValues.includes(value)) return null;

      const date = new Date(value);
      if (isNaN(date.getTime())) return value; // Return original if invalid

      switch (this.config.transformation.dateFormat) {
        case 'ISO':
          return date.toISOString().split('T')[0];
        case 'US':
          return date.toLocaleDateString('en-US');
        case 'EU':
          return date.toLocaleDateString('en-GB');
        default:
          return date.toISOString();
      }
    });

    // Number transformer
    this.transformers.set('number', (value) => {
      if (!value || this.config.transformation.nullValues.includes(value)) return null;

      // Handle different number formats
      let cleaned = value.toString().replace(/[^\d.,-]/g, '');

      if (this.config.transformation.numberFormat === 'EU') {
        // European format: 1.234.567,89 -> 1234567.89
        if (cleaned.includes(',') && cleaned.includes('.')) {
          cleaned = cleaned.replace(/\./g, '').replace(',', '.');
        } else if (cleaned.includes(',')) {
          cleaned = cleaned.replace(',', '.');
        }
      }

      const number = parseFloat(cleaned);
      return isNaN(number) ? value : number;
    });

    // Text transformer
    this.transformers.set('text', (value) => {
      if (!value || this.config.transformation.nullValues.includes(value)) return null;
      return value.toString().trim();
    });

    // Email transformer
    this.transformers.set('email', (value) => {
      if (!value) return null;
      return value.toString().toLowerCase().trim();
    });

    // Phone transformer
    this.transformers.set('phone', (value) => {
      if (!value) return null;
      // Standardize phone format
      const cleaned = value.toString().replace(/[^\d+]/g, '');
      if (cleaned.length === 10) return `+1${cleaned}`;
      if (cleaned.length === 11 && cleaned.startsWith('1')) return `+${cleaned}`;
      return cleaned.startsWith('+') ? cleaned : `+${cleaned}`;
    });
  }

  /**
   * Main migration function
   */
  async migrate(source, target, mapping = null) {
    console.log(`Starting migration: ${source} -> ${target}`);
    this.stats.startTime = new Date();

    // Ensure directories exist
    await this.ensureDirectories();

    // Load mapping if provided
    if (mapping) {
      await this.loadMapping(mapping);
    }

    // Detect source and target formats
    const sourceFormat = this.detectFormat(source);
    const targetFormat = this.detectFormat(target);

    console.log(`Detected formats: ${sourceFormat} -> ${targetFormat}`);

    // Create backup of source
    await this.createBackup(source);

    try {
      // Perform migration based on formats
      await this.performMigration(source, target, sourceFormat, targetFormat);

      this.stats.endTime = new Date();
      await this.generateMigrationReport();

      console.log('Migration completed successfully!');
      return this.getMigrationSummary();

    } catch (error) {
      console.error('Migration failed:', error);
      await this.rollback(source, target);
      throw error;
    }
  }

  /**
   * Ensure required directories exist
   */
  async ensureDirectories() {
    const dirs = [
      this.config.outputDir,
      this.config.backupDir,
      this.config.tempDir
    ];

    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  /**
   * Create backup of source file
   */
  async createBackup(source) {
    const backupPath = path.join(
      this.config.backupDir,
      `${path.basename(source)}.backup.${Date.now()}`
    );

    try {
      await fs.copyFile(source, backupPath);
      console.log(`Backup created: ${backupPath}`);
    } catch (error) {
      console.warn(`Failed to create backup: ${error.message}`);
    }
  }

  /**
   * Detect file format from extension or content
   */
  detectFormat(filePath) {
    const ext = path.extname(filePath).toLowerCase();

    const formatMap = {
      '.csv': 'csv',
      '.json': 'json',
      '.xml': 'xml',
      '.sql': 'sql',
      '.xlsx': 'excel',
      '.txt': 'text'
    };

    return formatMap[ext] || 'unknown';
  }

  /**
   * Load field mapping configuration
   */
  async loadMapping(mappingPath) {
    try {
      const mappingData = await fs.readFile(mappingPath, 'utf8');
      const mapping = JSON.parse(mappingData);

      this.schemas.set('source', mapping.source || {});
      this.schemas.set('target', mapping.target || {});
      this.stats.conversionMap = mapping.fieldMapping || {};

      console.log('Mapping loaded successfully');
    } catch (error) {
      console.warn(`Failed to load mapping: ${error.message}`);
    }
  }

  /**
   * Perform migration based on source and target formats
   */
  async performMigration(source, target, sourceFormat, targetFormat) {
    const migrationMethod = `migrate${sourceFormat.charAt(0).toUpperCase() + sourceFormat.slice(1)}To${targetFormat.charAt(0).toUpperCase() + targetFormat.slice(1)}`;

    if (typeof this[migrationMethod] === 'function') {
      await this[migrationMethod](source, target);
    } else {
      throw new Error(`Unsupported migration: ${sourceFormat} -> ${targetFormat}`);
    }
  }

  /**
   * Migrate CSV to JSON
   */
  async migrateCsvToJson(source, target) {
    console.log('Converting CSV to JSON...');

    const records = [];
    let batchRecords = [];

    return new Promise((resolve, reject) => {
      const processTransform = new Transform({
        objectMode: true,
        transform: (chunk, encoding, callback) => {
          this.stats.totalRecords++;

          try {
            const transformed = this.transformRecord(chunk, 'csv', 'json');

            if (this.validateRecord(transformed, 'target')) {
              batchRecords.push(transformed);
              this.stats.converted++;
            } else {
              this.stats.errors++;
              if (!this.config.validation.skipErrors) {
                return callback(new Error('Validation failed'));
              }
            }
          } catch (error) {
            this.stats.errors++;
            if (!this.config.validation.skipErrors) {
              return callback(error);
            }
          }

          // Process batch
          if (batchRecords.length >= this.config.batchSize) {
            records.push(...batchRecords);
            batchRecords = [];
            console.log(`Processed ${this.stats.totalRecords} records...`);
          }

          callback();
        }
      });

      createReadStream(source)
        .pipe(csv())
        .pipe(processTransform)
        .on('finish', async () => {
          // Add remaining records
          records.push(...batchRecords);

          // Write JSON file
          await fs.writeFile(target, JSON.stringify(records, null, 2));
          console.log(`JSON file created: ${target}`);
          resolve();
        })
        .on('error', reject);
    });
  }

  /**
   * Migrate JSON to CSV
   */
  async migrateJsonToCsv(source, target) {
    console.log('Converting JSON to CSV...');

    const data = await fs.readFile(source, 'utf8');
    const records = JSON.parse(data);

    if (!Array.isArray(records)) {
      throw new Error('JSON must contain an array of records');
    }

    const csvStream = createWriteStream(target);
    let headerWritten = false;

    for (let i = 0; i < records.length; i += this.config.batchSize) {
      const batch = records.slice(i, i + this.config.batchSize);

      for (const record of batch) {
        this.stats.totalRecords++;

        try {
          const transformed = this.transformRecord(record, 'json', 'csv');

          if (this.validateRecord(transformed, 'target')) {
            // Write header on first record
            if (!headerWritten) {
              const headers = Object.keys(transformed).join(',') + '\n';
              csvStream.write(headers);
              headerWritten = true;
            }

            // Write data row
            const values = Object.values(transformed)
              .map(value => `"${String(value || '').replace(/"/g, '""')}"`)
              .join(',') + '\n';

            csvStream.write(values);
            this.stats.converted++;
          } else {
            this.stats.errors++;
          }
        } catch (error) {
          this.stats.errors++;
          if (!this.config.validation.skipErrors) {
            throw error;
          }
        }
      }

      console.log(`Processed ${Math.min(i + this.config.batchSize, records.length)} records...`);
    }

    csvStream.end();
    console.log(`CSV file created: ${target}`);
  }

  /**
   * Migrate XML to JSON
   */
  async migrateXmlToJson(source, target) {
    console.log('Converting XML to JSON...');

    const xmlData = await fs.readFile(source, 'utf8');
    const parser = new xml2js.Parser({
      explicitArray: false,
      mergeAttrs: true,
      normalize: true,
      normalizeTags: true,
      trim: true
    });

    return new Promise((resolve, reject) => {
      parser.parseString(xmlData, async (err, result) => {
        if (err) return reject(err);

        try {
          // Transform XML structure to flat records if needed
          const records = this.flattenXmlStructure(result);

          // Process records in batches
          const processedRecords = [];

          for (let i = 0; i < records.length; i += this.config.batchSize) {
            const batch = records.slice(i, i + this.config.batchSize);

            for (const record of batch) {
              this.stats.totalRecords++;

              try {
                const transformed = this.transformRecord(record, 'xml', 'json');

                if (this.validateRecord(transformed, 'target')) {
                  processedRecords.push(transformed);
                  this.stats.converted++;
                } else {
                  this.stats.errors++;
                }
              } catch (error) {
                this.stats.errors++;
                if (!this.config.validation.skipErrors) {
                  throw error;
                }
              }
            }

            console.log(`Processed ${Math.min(i + this.config.batchSize, records.length)} records...`);
          }

          await fs.writeFile(target, JSON.stringify(processedRecords, null, 2));
          console.log(`JSON file created: ${target}`);
          resolve();

        } catch (error) {
          reject(error);
        }
      });
    });
  }

  /**
   * Flatten XML structure into array of records
   */
  flattenXmlStructure(xmlObj) {
    // This is a simplified implementation
    // In practice, you'd need more sophisticated XML structure handling

    if (Array.isArray(xmlObj)) {
      return xmlObj;
    }

    // Look for common patterns like <records><record>...</record></records>
    const keys = Object.keys(xmlObj);
    for (const key of keys) {
      const value = xmlObj[key];
      if (Array.isArray(value)) {
        return value;
      }
      if (typeof value === 'object' && value !== null) {
        const subResult = this.flattenXmlStructure(value);
        if (Array.isArray(subResult)) {
          return subResult;
        }
      }
    }

    // If no array found, treat the entire object as a single record
    return [xmlObj];
  }

  /**
   * Transform record based on field mapping and data types
   */
  transformRecord(record, sourceFormat, targetFormat) {
    const transformed = {};

    // Apply field mapping if available
    const fieldMapping = this.stats.conversionMap;

    for (const [sourceField, value] of Object.entries(record)) {
      const targetField = fieldMapping[sourceField] || sourceField;

      // Apply data transformation based on field type
      const fieldType = this.getFieldType(targetField);
      const transformer = this.transformers.get(fieldType);

      transformed[targetField] = transformer ? transformer(value) : value;
    }

    return transformed;
  }

  /**
   * Get field type from schema or infer from value
   */
  getFieldType(fieldName) {
    const targetSchema = this.schemas.get('target');
    if (targetSchema && targetSchema[fieldName]) {
      return targetSchema[fieldName].type || 'text';
    }

    // Default type inference
    if (fieldName.includes('date') || fieldName.includes('time')) return 'date';
    if (fieldName.includes('email')) return 'email';
    if (fieldName.includes('phone')) return 'phone';
    if (fieldName.includes('amount') || fieldName.includes('price') || fieldName.includes('cost')) return 'number';

    return 'text';
  }

  /**
   * Validate record against schema
   */
  validateRecord(record, schemaType) {
    if (!this.config.validation.enabled) return true;

    const schema = this.schemas.get(schemaType);
    if (!schema) return true;

    for (const [field, rules] of Object.entries(schema)) {
      const value = record[field];

      // Required field validation
      if (rules.required && (value === null || value === undefined || value === '')) {
        console.warn(`Validation failed: Required field '${field}' is missing`);
        return false;
      }

      // Type validation
      if (value !== null && rules.type) {
        if (!this.validateFieldType(value, rules.type)) {
          console.warn(`Validation failed: Field '${field}' has invalid type`);
          return false;
        }
      }

      // Custom validation
      if (rules.validate && typeof rules.validate === 'function') {
        if (!rules.validate(value)) {
          console.warn(`Validation failed: Custom validation for field '${field}' failed`);
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Validate field type
   */
  validateFieldType(value, expectedType) {
    switch (expectedType) {
      case 'number':
        return !isNaN(parseFloat(value));
      case 'date':
        return !isNaN(Date.parse(value));
      case 'email':
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      case 'phone':
        return /^\+?[\d\s\-\(\)]{10,}$/.test(value);
      case 'boolean':
        return typeof value === 'boolean' || ['true', 'false', '1', '0'].includes(String(value).toLowerCase());
      default:
        return true;
    }
  }

  /**
   * Generate migration report
   */
  async generateMigrationReport() {
    const report = {
      migration: {
        startTime: this.stats.startTime.toISOString(),
        endTime: this.stats.endTime.toISOString(),
        duration: this.stats.endTime - this.stats.startTime,
        totalRecords: this.stats.totalRecords,
        converted: this.stats.converted,
        errors: this.stats.errors,
        skipped: this.stats.skipped,
        successRate: ((this.stats.converted / this.stats.totalRecords) * 100).toFixed(2)
      },
      configuration: this.config,
      mapping: this.stats.conversionMap
    };

    const reportPath = path.join(this.config.outputDir, 'migration-report.json');
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2));

    console.log('\n=== MIGRATION REPORT ===');
    console.log(`Total records: ${report.migration.totalRecords}`);
    console.log(`Successfully converted: ${report.migration.converted}`);
    console.log(`Errors: ${report.migration.errors}`);
    console.log(`Success rate: ${report.migration.successRate}%`);
    console.log(`Duration: ${report.migration.duration}ms`);
    console.log(`Report saved to: ${reportPath}`);
  }

  /**
   * Get migration summary
   */
  getMigrationSummary() {
    return {
      totalRecords: this.stats.totalRecords,
      converted: this.stats.converted,
      errors: this.stats.errors,
      successRate: ((this.stats.converted / this.stats.totalRecords) * 100).toFixed(2),
      duration: this.stats.endTime - this.stats.startTime
    };
  }

  /**
   * Rollback migration on failure
   */
  async rollback(source, target) {
    console.log('Rolling back migration...');

    try {
      // Remove partially created target file
      await fs.unlink(target);
      console.log('Target file removed');
    } catch (error) {
      console.warn('Failed to remove target file:', error.message);
    }

    // Additional rollback logic can be added here
    console.log('Rollback completed');
  }

  /**
   * Batch migrate multiple files
   */
  async batchMigrate(sourceDir, targetDir, pattern = '*', mapping = null) {
    console.log(`Starting batch migration: ${sourceDir} -> ${targetDir}`);

    const files = await fs.readdir(sourceDir);
    const matchingFiles = files.filter(file =>
      pattern === '*' || file.includes(pattern)
    );

    const results = [];

    for (const file of matchingFiles) {
      const sourcePath = path.join(sourceDir, file);
      const targetPath = path.join(targetDir, this.generateTargetFilename(file));

      try {
        console.log(`\n--- Migrating: ${file} ---`);
        const result = await this.migrate(sourcePath, targetPath, mapping);
        results.push({ file, status: 'success', ...result });
      } catch (error) {
        console.error(`Migration failed for ${file}:`, error.message);
        results.push({ file, status: 'error', error: error.message });
      }

      // Reset stats for next file
      this.resetStats();
    }

    return results;
  }

  /**
   * Generate target filename with appropriate extension
   */
  generateTargetFilename(sourceFile) {
    const baseName = path.parse(sourceFile).name;
    return `${baseName}_migrated.json`; // Default to JSON
  }

  /**
   * Reset statistics for next migration
   */
  resetStats() {
    this.stats = {
      totalRecords: 0,
      converted: 0,
      errors: 0,
      skipped: 0,
      filesProcessed: 0,
      startTime: null,
      endTime: null,
      conversionMap: this.stats.conversionMap // Keep mapping
    };
  }
}

// CLI Interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length < 2) {
    console.log('Usage: node data-migrator.js <source> <target> [mapping-file] [config-file]');
    console.log('Examples:');
    console.log('  node data-migrator.js input.csv output.json');
    console.log('  node data-migrator.js data/ migrated/ mapping.json config.json');
    process.exit(1);
  }

  const [source, target, mappingFile, configFile] = args;

  let config = {};
  if (configFile) {
    try {
      const configData = await fs.readFile(configFile, 'utf8');
      config = JSON.parse(configData);
    } catch (error) {
      console.error(`Error loading config: ${error.message}`);
      process.exit(1);
    }
  }

  const migrator = new DataMigrator(config);

  try {
    const sourceStat = await fs.stat(source);

    if (sourceStat.isFile()) {
      await migrator.migrate(source, target, mappingFile);
    } else if (sourceStat.isDirectory()) {
      await fs.mkdir(target, { recursive: true });
      await migrator.batchMigrate(source, target, '*', mappingFile);
    }

    console.log('\nMigration completed successfully!');
  } catch (error) {
    console.error(`Migration failed: ${error.message}`);
    process.exit(1);
  }
}

// Export for testing
module.exports = DataMigrator;

// Run CLI if called directly
if (require.main === module) {
  main().catch(console.error);
}