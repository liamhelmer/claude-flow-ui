#!/usr/bin/env node

// Simple test script to verify ANSI escape codes work properly
// This should display colored text and cursor movements

console.log('\n🧪 Testing ANSI Escape Sequences:');

// Test basic colors
console.log('\x1b[31mRed text\x1b[0m');
console.log('\x1b[32mGreen text\x1b[0m'); 
console.log('\x1b[33mYellow text\x1b[0m');
console.log('\x1b[34mBlue text\x1b[0m');
console.log('\x1b[35mMagenta text\x1b[0m');
console.log('\x1b[36mCyan text\x1b[0m');

// Test bold and bright colors
console.log('\x1b[1;31mBold red text\x1b[0m');
console.log('\x1b[1;32mBold green text\x1b[0m');

// Test background colors
console.log('\x1b[41;37m White text on red background \x1b[0m');
console.log('\x1b[44;33m Yellow text on blue background \x1b[0m');

// Test cursor movement and positioning
process.stdout.write('\x1b[2J\x1b[H'); // Clear screen and go to home
process.stdout.write('\x1b[10;10H'); // Move to row 10, col 10
process.stdout.write('This text is at position 10,10');
process.stdout.write('\x1b[12;5H'); // Move to row 12, col 5
process.stdout.write('This text is at position 12,5');

// Test character input/output
console.log('\n\n📝 Type some characters to test input display:');
process.stdin.setRawMode(true);
process.stdin.resume();

let chars = [];
process.stdin.on('data', (key) => {
  if (key.toString('hex') === '03') { // Ctrl+C
    console.log('\n✅ ANSI test complete');
    process.exit(0);
  }
  
  if (key.toString('hex') === '0d') { // Enter
    console.log('\nYou typed: ' + chars.join(''));
    chars = [];
  } else {
    chars.push(key.toString());
    process.stdout.write(key);
  }
});

console.log('Press Ctrl+C to exit');