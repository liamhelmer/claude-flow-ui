#!/usr/bin/env node

/**
 * Demo script to show tmux termination and exit code capture
 */

const TmuxManager = require('../src/lib/tmux-manager');
const gracefulShutdown = require('../src/utils/gracefulShutdown');

async function demonstrateTmuxExitCapture() {
    console.log('🚀 Starting Tmux Exit Code Capture Demo\n');

    // Create and register TmuxManager
    const tmuxManager = gracefulShutdown.createTmuxManager(process.cwd(), 'DemoTmux');

    console.log('📝 Creating tmux session with npx claude-flow@alpha --help command...\n');

    // Create a session that runs claude-flow with --help argument
    const session = await tmuxManager.createSession(
        'demo-claude-flow',
        'npx',
        ['claude-flow@alpha', '--help'],
        120,  // cols
        30    // rows
    );

    console.log(`✅ Session created: ${session.name}`);
    console.log(`📁 Socket path: ${session.socketPath}\n`);

    // Connect to the session
    const pty = await tmuxManager.connectToSession(session.name);

    console.log('🔌 Connected to session, monitoring output...\n');
    console.log('─'.repeat(50));
    console.log('TMUX OUTPUT:');
    console.log('─'.repeat(50));

    // Monitor output
    pty.onData((data) => {
        process.stdout.write(data);
    });

    // Monitor exit
    pty.onExit((exitInfo) => {
        console.log('\n' + '─'.repeat(50));
        console.log(`\n🎯 Command completed!`);
        console.log(`   Exit Code: ${exitInfo.exitCode}`);
        console.log(`   Signal: ${exitInfo.signal || 'none'}`);

        if (exitInfo.signal === 'COMMAND_COMPLETED') {
            console.log(`   ✅ claude-flow command finished with exit code: ${exitInfo.exitCode}`);
        } else if (exitInfo.signal === 'SOCKET_TERMINATED') {
            console.log(`   ⚠️ Socket was terminated`);
        }

        console.log('\n📊 Exit code is now available in server console!');
        console.log('🧹 Application will clean up and shut down...\n');
    });

    // Wait for command to complete
    console.log('\nℹ️ Waiting for command to complete...\n');
}

// Run the demo
demonstrateTmuxExitCapture().catch(err => {
    console.error('❌ Demo failed:', err);
    process.exit(1);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT, shutting down gracefully...');
    gracefulShutdown.shutdown('SIGINT');
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
    gracefulShutdown.shutdown('SIGTERM');
});