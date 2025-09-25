#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const csv = require('csv-parser');
const { createWriteStream, createReadStream } = require('fs');
const { Transform } = require('stream');

/**
 * CSV Data Cleaner - Batch Processing Example
 *
 * This example demonstrates batch processing of customer data files:
 * - Data validation and cleaning
 * - Email format validation
 * - Phone number standardization
 * - Address normalization
 * - Duplicate detection and removal
 * - Error logging and reporting
 */

class CSVCleaner {
  constructor(config = {}) {
    this.config = {
      batchSize: 1000,
      outputDir: './cleaned',
      errorDir: './errors',
      duplicateHandling: 'remove', // 'remove', 'flag', 'separate'
      validationRules: {
        email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        phone: /^\+?[\d\s\-\(\)]{10,}$/,
        required: ['email', 'firstName', 'lastName']
      },
      transformations: {
        email: 'lowercase',
        phone: 'standardize',
        name: 'titlecase'
      },
      ...config
    };

    this.stats = {
      processed: 0,
      cleaned: 0,
      errors: 0,
      duplicates: 0,
      startTime: null,
      endTime: null
    };

    this.seenEmails = new Set();
    this.errors = [];
  }

  /**
   * Process a single CSV file
   */
  async processFile(inputFile) {
    console.log(`Processing file: ${inputFile}`);
    this.stats.startTime = new Date();

    const outputFile = path.join(
      this.config.outputDir,
      `cleaned_${path.basename(inputFile)}`
    );
    const errorFile = path.join(
      this.config.errorDir,
      `errors_${path.basename(inputFile)}`
    );

    // Ensure output directories exist
    await fs.mkdir(this.config.outputDir, { recursive: true });
    await fs.mkdir(this.config.errorDir, { recursive: true });

    const writeStream = createWriteStream(outputFile);
    const errorStream = createWriteStream(errorFile);

    // Write headers
    const isFirstFile = true;
    let headerWritten = false;
    let errorHeaderWritten = false;

    return new Promise((resolve, reject) => {
      const cleanTransform = new Transform({
        objectMode: true,
        transform: (chunk, encoding, callback) => {
          this.stats.processed++;

          try {
            const cleanedRow = this.cleanRow(chunk);

            if (cleanedRow.isValid) {
              if (!headerWritten) {
                writeStream.write(Object.keys(cleanedRow.data).join(',') + '\n');
                headerWritten = true;
              }

              const csvRow = Object.values(cleanedRow.data)
                .map(value => `"${String(value).replace(/"/g, '""')}"`)
                .join(',') + '\n';

              writeStream.write(csvRow);
              this.stats.cleaned++;
            } else {
              if (!errorHeaderWritten) {
                const errorHeader = [...Object.keys(chunk), 'error_reason'].join(',') + '\n';
                errorStream.write(errorHeader);
                errorHeaderWritten = true;
              }

              const errorRow = [...Object.values(chunk), cleanedRow.error]
                .map(value => `"${String(value).replace(/"/g, '""')}"`)
                .join(',') + '\n';

              errorStream.write(errorRow);
              this.stats.errors++;
            }
          } catch (error) {
            console.error('Transform error:', error);
            this.stats.errors++;
          }

          callback();
        }
      });

      createReadStream(inputFile)
        .pipe(csv())
        .pipe(cleanTransform)
        .on('finish', () => {
          writeStream.end();
          errorStream.end();
          this.stats.endTime = new Date();
          this.printStats();
          resolve();
        })
        .on('error', reject);
    });
  }

  /**
   * Clean and validate a single data row
   */
  cleanRow(row) {
    const cleaned = { ...row };
    const errors = [];

    try {
      // Check required fields
      for (const field of this.config.validationRules.required) {
        if (!cleaned[field] || String(cleaned[field]).trim() === '') {
          errors.push(`Missing required field: ${field}`);
        }
      }

      // Email validation and transformation
      if (cleaned.email) {
        cleaned.email = cleaned.email.toString().trim().toLowerCase();
        if (!this.config.validationRules.email.test(cleaned.email)) {
          errors.push('Invalid email format');
        } else if (this.seenEmails.has(cleaned.email)) {
          this.stats.duplicates++;
          if (this.config.duplicateHandling === 'remove') {
            errors.push('Duplicate email address');
          } else if (this.config.duplicateHandling === 'flag') {
            cleaned.duplicate_flag = true;
          }
        } else {
          this.seenEmails.add(cleaned.email);
        }
      }

      // Phone number standardization
      if (cleaned.phone) {
        cleaned.phone = this.standardizePhone(cleaned.phone);
        if (!this.config.validationRules.phone.test(cleaned.phone)) {
          errors.push('Invalid phone format');
        }
      }

      // Name formatting
      if (cleaned.firstName) {
        cleaned.firstName = this.titleCase(cleaned.firstName.toString().trim());
      }
      if (cleaned.lastName) {
        cleaned.lastName = this.titleCase(cleaned.lastName.toString().trim());
      }

      // Address normalization
      if (cleaned.address) {
        cleaned.address = this.normalizeAddress(cleaned.address);
      }

      // Data type validations
      if (cleaned.age && (isNaN(cleaned.age) || cleaned.age < 0 || cleaned.age > 150)) {
        errors.push('Invalid age value');
      }

      // Date validations
      if (cleaned.birthDate) {
        const date = new Date(cleaned.birthDate);
        if (isNaN(date.getTime())) {
          errors.push('Invalid birth date format');
        } else {
          cleaned.birthDate = date.toISOString().split('T')[0];
        }
      }

      return {
        isValid: errors.length === 0,
        data: cleaned,
        error: errors.join('; ')
      };

    } catch (error) {
      return {
        isValid: false,
        data: row,
        error: `Processing error: ${error.message}`
      };
    }
  }

  /**
   * Standardize phone number format
   */
  standardizePhone(phone) {
    // Remove all non-digit characters except +
    const cleaned = phone.toString().replace(/[^\d+]/g, '');

    // Handle US phone numbers
    if (cleaned.length === 10) {
      return `+1${cleaned}`;
    } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
      return `+${cleaned}`;
    }

    return cleaned.startsWith('+') ? cleaned : `+${cleaned}`;
  }

  /**
   * Convert text to title case
   */
  titleCase(text) {
    return text.toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
  }

  /**
   * Normalize address format
   */
  normalizeAddress(address) {
    return address.toString()
      .trim()
      .replace(/\s+/g, ' ')
      .replace(/\bSt\b/gi, 'Street')
      .replace(/\bAve\b/gi, 'Avenue')
      .replace(/\bRd\b/gi, 'Road')
      .replace(/\bBlvd\b/gi, 'Boulevard');
  }

  /**
   * Process multiple files in batch
   */
  async processBatch(inputFiles) {
    console.log(`Processing ${inputFiles.length} files in batch...`);

    for (const file of inputFiles) {
      await this.processFile(file);
      // Reset stats for each file except cumulative counters
      this.seenEmails.clear();
    }

    await this.generateSummaryReport();
  }

  /**
   * Generate processing summary report
   */
  async generateSummaryReport() {
    const report = {
      summary: {
        totalProcessed: this.stats.processed,
        successfullyCleaned: this.stats.cleaned,
        errorsFound: this.stats.errors,
        duplicatesDetected: this.stats.duplicates,
        processingTime: this.stats.endTime - this.stats.startTime,
        successRate: ((this.stats.cleaned / this.stats.processed) * 100).toFixed(2)
      },
      configuration: this.config,
      timestamp: new Date().toISOString()
    };

    const reportFile = path.join(this.config.outputDir, 'processing_report.json');
    await fs.writeFile(reportFile, JSON.stringify(report, null, 2));

    console.log('\n=== PROCESSING SUMMARY ===');
    console.log(`Total processed: ${report.summary.totalProcessed}`);
    console.log(`Successfully cleaned: ${report.summary.successfullyCleaned}`);
    console.log(`Errors found: ${report.summary.errorsFound}`);
    console.log(`Duplicates detected: ${report.summary.duplicatesDetected}`);
    console.log(`Success rate: ${report.summary.successRate}%`);
    console.log(`Processing time: ${report.summary.processingTime}ms`);
    console.log(`Report saved to: ${reportFile}`);
  }

  /**
   * Print processing statistics
   */
  printStats() {
    const duration = this.stats.endTime - this.stats.startTime;
    const rate = Math.round(this.stats.processed / (duration / 1000));

    console.log(`\nProcessed: ${this.stats.processed} records`);
    console.log(`Cleaned: ${this.stats.cleaned} records`);
    console.log(`Errors: ${this.stats.errors} records`);
    console.log(`Duplicates: ${this.stats.duplicates} records`);
    console.log(`Rate: ${rate} records/second`);
    console.log(`Duration: ${duration}ms`);
  }
}

// CLI Interface
async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log('Usage: node csv-cleaner.js <input-file-or-directory> [config-file]');
    console.log('Example: node csv-cleaner.js ./data/customers.csv');
    console.log('Example: node csv-cleaner.js ./data/ ./config/cleaner-config.json');
    process.exit(1);
  }

  const inputPath = args[0];
  const configPath = args[1];

  let config = {};
  if (configPath) {
    try {
      const configData = await fs.readFile(configPath, 'utf8');
      config = JSON.parse(configData);
    } catch (error) {
      console.error(`Error loading config: ${error.message}`);
      process.exit(1);
    }
  }

  const cleaner = new CSVCleaner(config);

  try {
    const stat = await fs.stat(inputPath);

    if (stat.isFile()) {
      await cleaner.processFile(inputPath);
    } else if (stat.isDirectory()) {
      const files = await fs.readdir(inputPath);
      const csvFiles = files
        .filter(file => file.endsWith('.csv'))
        .map(file => path.join(inputPath, file));

      if (csvFiles.length === 0) {
        console.log('No CSV files found in directory');
        process.exit(1);
      }

      await cleaner.processBatch(csvFiles);
    }
  } catch (error) {
    console.error(`Error processing files: ${error.message}`);
    process.exit(1);
  }
}

// Export for testing
module.exports = CSVCleaner;

// Run CLI if called directly
if (require.main === module) {
  main().catch(console.error);
}