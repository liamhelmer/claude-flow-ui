#!/usr/bin/env node

/**
 * Demonstration of the multi-terminal functionality in claude-flow-ui
 * Run this after starting the server with: npm run claude-flow-ui
 */

const http = require('http');
const readline = require('readline');

const PORT = process.env.PORT || 5173;
const HOST = 'localhost';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Helper function for HTTP requests
function request(path, method = 'GET', data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HOST,
      port: PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(body) });
        } catch {
          resolve({ status: res.statusCode, body });
        }
      });
    });

    req.on('error', reject);

    if (data) {
      req.write(JSON.stringify(data));
    }

    req.end();
  });
}

async function listTerminals() {
  const response = await request('/api/terminals');
  console.log('\n📋 Active Terminals:');
  response.body.forEach((terminal, index) => {
    console.log(`   ${index + 1}. ${terminal.name} (${terminal.id})`);
    console.log(`      Command: ${terminal.command || 'shell'}`);
  });
  return response.body;
}

async function spawnTerminal(name) {
  const response = await request('/api/terminals/spawn', 'POST', {
    name: name || `Bash ${Date.now()}`,
    command: '/bin/bash --login'
  });

  if (response.status === 200) {
    console.log(`\n✅ Spawned terminal: ${response.body.name}`);
    console.log(`   ID: ${response.body.id}`);
  } else {
    console.log(`\n❌ Failed to spawn terminal: ${response.body.error || 'Unknown error'}`);
  }

  return response;
}

async function closeTerminal(id) {
  const response = await request(`/api/terminals/${id}`, 'DELETE');

  if (response.status === 200) {
    console.log(`\n✅ Closed terminal: ${id}`);
  } else if (response.status === 400) {
    console.log(`\n❌ Cannot close: ${response.body.error}`);
  } else {
    console.log(`\n❌ Failed to close terminal: ${response.body.error || 'Unknown error'}`);
  }

  return response;
}

async function mainMenu() {
  console.log('\n' + '='.repeat(60));
  console.log('CLAUDE FLOW UI - TERMINAL MANAGER DEMO');
  console.log('='.repeat(60));
  console.log('\nMake sure the server is running:');
  console.log('  npm run claude-flow-ui');
  console.log(`\nConnecting to http://${HOST}:${PORT}`);

  // Test connection
  try {
    await request('/api/health');
    console.log('✅ Server is running!\n');
  } catch (error) {
    console.log('❌ Cannot connect to server. Make sure it\'s running.\n');
    process.exit(1);
  }

  const showMenu = async () => {
    console.log('\n' + '-'.repeat(40));
    console.log('Options:');
    console.log('  1. List all terminals');
    console.log('  2. Spawn new terminal');
    console.log('  3. Close a terminal');
    console.log('  4. Spawn multiple terminals (demo)');
    console.log('  5. Exit');
    console.log('-'.repeat(40));

    rl.question('\nSelect option (1-5): ', async (answer) => {
      switch(answer) {
        case '1':
          await listTerminals();
          showMenu();
          break;

        case '2':
          rl.question('Enter terminal name (or press Enter for default): ', async (name) => {
            await spawnTerminal(name || `Bash ${new Date().toLocaleTimeString()}`);
            showMenu();
          });
          break;

        case '3':
          const terminals = await listTerminals();
          if (terminals.length <= 1) {
            console.log('\n⚠️  Only the main terminal exists (cannot be closed)');
            showMenu();
          } else {
            rl.question('Enter terminal number to close: ', async (num) => {
              const index = parseInt(num) - 1;
              if (index >= 0 && index < terminals.length) {
                await closeTerminal(terminals[index].id);
              } else {
                console.log('Invalid selection');
              }
              showMenu();
            });
          }
          break;

        case '4':
          console.log('\n🎯 Spawning multiple terminals for demo...');
          await spawnTerminal('Development Shell');
          await spawnTerminal('Build Terminal');
          await spawnTerminal('Test Runner');
          await listTerminals();
          console.log('\n✨ Check the UI sidebar to see all terminals!');
          showMenu();
          break;

        case '5':
          console.log('\nGoodbye! 👋');
          process.exit(0);
          break;

        default:
          console.log('Invalid option');
          showMenu();
      }
    });
  };

  await listTerminals();
  showMenu();
}

// Start the demo
console.clear();
mainMenu().catch(console.error);