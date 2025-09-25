import { FullConfig } from '@playwright/test';
import path from 'path';
import fs from 'fs/promises';

/**
 * Global teardown for Playwright E2E coverage collection
 * Finalizes coverage data and prepares for merging
 */
async function globalTeardown(config: FullConfig) {
  console.log('🎭 Finalizing Playwright E2E coverage collection...');

  const coverageDir = path.resolve('./coverage/playwright');

  try {
    // Read coverage state
    const stateFile = path.join(coverageDir, 'coverage-state.json');
    let coverageState = { setupComplete: false, testFiles: [] };

    try {
      const stateData = await fs.readFile(stateFile, 'utf8');
      coverageState = JSON.parse(stateData);
    } catch (error) {
      console.warn('⚠️  Could not read coverage state:', error.message);
    }

    // Finalize coverage collection
    const finalState = {
      ...coverageState,
      endTime: new Date().toISOString(),
      teardownComplete: true,
      totalTestFiles: coverageState.testFiles?.length || 0,
    };

    await fs.writeFile(stateFile, JSON.stringify(finalState, null, 2));

    // Create coverage summary for this session
    const coverageSummary = {
      metadata: {
        type: 'playwright-e2e',
        timestamp: new Date().toISOString(),
        duration: finalState.endTime && finalState.startTime ?
          new Date(finalState.endTime).getTime() - new Date(finalState.startTime).getTime() :
          0,
        testFiles: finalState.totalTestFiles,
        setupComplete: finalState.setupComplete,
      },
      files: [],
      coverage: {}
    };

    // Collect all coverage files created during tests
    try {
      const files = await fs.readdir(coverageDir);
      const coverageFiles = files.filter(f =>
        f.endsWith('.json') && (f.includes('coverage') || f.includes('cov'))
      );

      for (const file of coverageFiles) {
        try {
          const filePath = path.join(coverageDir, file);
          const data = JSON.parse(await fs.readFile(filePath, 'utf8'));

          if (data.js || data.css || data.coverage) {
            coverageSummary.files.push({
              filename: file,
              type: data.type || 'unknown',
              timestamp: data.timestamp || new Date().toISOString(),
              entries: Array.isArray(data.js) ? data.js.length : 0
            });
          }
        } catch (error) {
          console.warn(`⚠️  Could not process coverage file ${file}:`, error.message);
        }
      }
    } catch (error) {
      console.warn('⚠️  Could not scan coverage directory:', error.message);
    }

    // Write final coverage summary
    await fs.writeFile(
      path.join(coverageDir, 'playwright-coverage-summary.json'),
      JSON.stringify(coverageSummary, null, 2)
    );

    // Generate NYC-compatible coverage format if we have data
    try {
      await generateNycCompatibleCoverage(coverageDir);
    } catch (error) {
      console.warn('⚠️  Could not generate NYC-compatible coverage:', error.message);
    }

    console.log(`✅ Playwright E2E coverage collection finalized`);
    console.log(`📊 Coverage files: ${coverageSummary.files.length}`);
    console.log(`📁 Coverage directory: ${coverageDir}`);

  } catch (error) {
    console.error('❌ Coverage teardown failed:', error.message);
    console.error('Coverage data may be incomplete');
  }
}

/**
 * Convert Playwright coverage data to NYC-compatible format
 */
async function generateNycCompatibleCoverage(coverageDir: string) {
  const files = await fs.readdir(coverageDir);
  const coverageFiles = files.filter(f => f.includes('coverage') && f.endsWith('.json'));

  const nycCoverage: { [key: string]: any } = {};

  for (const file of coverageFiles) {
    try {
      const filePath = path.join(coverageDir, file);
      const data = JSON.parse(await fs.readFile(filePath, 'utf8'));

      if (data.js && Array.isArray(data.js)) {
        for (const entry of data.js) {
          if (entry.url && entry.ranges && !entry.url.includes('node_modules')) {
            // Convert Playwright coverage to NYC format
            const normalizedUrl = entry.url
              .replace('http://localhost:11235', '')
              .replace(/^\//, '');

            if (normalizedUrl && !normalizedUrl.startsWith('_next/')) {
              nycCoverage[normalizedUrl] = convertPlaywrightToNyc(entry);
            }
          }
        }
      }
    } catch (error) {
      console.warn(`Could not process ${file} for NYC conversion:`, error.message);
    }
  }

  if (Object.keys(nycCoverage).length > 0) {
    await fs.writeFile(
      path.join(coverageDir, 'coverage-final.json'),
      JSON.stringify(nycCoverage, null, 2)
    );
    console.log('✅ Generated NYC-compatible coverage format');
  }
}

/**
 * Convert Playwright coverage entry to NYC format
 */
function convertPlaywrightToNyc(entry: any) {
  // This is a simplified conversion
  // In a real implementation, you'd need more sophisticated parsing
  const nycEntry = {
    path: entry.url,
    statementMap: {},
    fnMap: {},
    branchMap: {},
    s: {},
    f: {},
    b: {},
    inputSourceMap: null,
    hash: Math.random().toString(36).substr(2, 9)
  };

  // Convert ranges to statement coverage
  if (entry.ranges) {
    entry.ranges.forEach((range: any, index: number) => {
      nycEntry.statementMap[index] = {
        start: { line: 1, column: range.start || 0 },
        end: { line: 1, column: range.end || 0 }
      };
      nycEntry.s[index] = range.count || 0;
    });
  }

  return nycEntry;
}

export default globalTeardown;