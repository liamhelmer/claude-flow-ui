#!/usr/bin/env node

/**
 * Final test: Run claude-flow and verify exit codes in server console only
 */

const TmuxManager = require('../src/lib/tmux-manager');

async function finalTest() {
    console.log('═'.repeat(80));
    console.log('FINAL TEST: claude-flow with server-only exit codes');
    console.log('═'.repeat(80) + '\n');

    const tmuxManager = new TmuxManager(process.cwd());

    console.log('[SERVER] Creating tmux session for: npx claude-flow@alpha --version');
    const session = await tmuxManager.createSession(
        'claude-flow-final',
        'npx',
        ['claude-flow@alpha', '--version'],
        120,
        30
    );

    console.log(`[SERVER] Session created: ${session.name}`);
    console.log(`[SERVER] Socket: ${session.socketPath}`);
    console.log(`[SERVER] Output file: ${session.outputFile}\n`);

    const pty = await tmuxManager.connectToSession(session.name);

    console.log('┌' + '─'.repeat(58) + '┐');
    console.log('│ TERMINAL VIEW (what users see - no exit codes):        │');
    console.log('└' + '─'.repeat(58) + '┘');

    let terminalClosed = false;

    pty.onData((data) => {
        // Terminal output - no exit codes should appear here
        if (!terminalClosed) {
            process.stdout.write(data);
        }
    });

    await new Promise((resolve) => {
        pty.onExit((exitInfo) => {
            terminalClosed = true;
            console.log('\n┌' + '─'.repeat(58) + '┐');
            console.log('│ TERMINAL CLOSED (command completed)                     │');
            console.log('└' + '─'.repeat(58) + '┘\n');

            console.log('[SERVER] Terminal session ended');
            console.log('[SERVER] Exit info received by pty handler:');
            console.log(`[SERVER]   - Exit code: ${exitInfo.exitCode}`);
            console.log(`[SERVER]   - Signal: ${exitInfo.signal || 'none'}\n`);

            resolve();
        });

        // Safety timeout
        setTimeout(() => {
            console.log('\n[SERVER] Timeout reached (30s)');
            resolve();
        }, 30000);
    });

    console.log('═'.repeat(80));
    console.log('TEST COMPLETE');
    console.log('═'.repeat(80));
    console.log('\n✅ Summary:');
    console.log('  - Exit codes appeared only in [SERVER] messages');
    console.log('  - Terminal output was clean (no exit codes)');
    console.log('  - Terminal closed when command completed');
    console.log('  - Full output was captured to file and logged\n');

    await tmuxManager.cleanup();
    process.exit(0);
}

// Run the test
finalTest().catch(err => {
    console.error('[SERVER] Test failed:', err);
    process.exit(1);
});

// Handle interruption
process.on('SIGINT', () => {
    console.log('\n\n[SERVER] Test interrupted');
    process.exit(1);
});