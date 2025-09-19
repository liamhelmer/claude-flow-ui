# Manual Terminal Input Testing Protocol

## Overview
This document provides step-by-step manual testing procedures to verify terminal input functionality works correctly after fixes have been implemented.

## Prerequisites
- Terminal application is running and accessible
- Browser with developer tools available
- Basic terminal commands knowledge

## Test Environment Setup

### 1. Start Terminal Application
```bash
# Start in production mode for realistic testing
npm run claude-flow-ui -- --port 11350 --terminal-size 100x30 hive-mind spawn wait
```

### 2. Open Browser and Navigate
- Open browser (Chrome/Firefox recommended)
- Navigate to `http://localhost:11350`
- Open Developer Tools (F12)
- Go to Console tab to monitor events

## Test Suite 1: Basic Terminal Input

### Test 1.1: Single Command Input
**Objective**: Verify basic terminal input works

**Steps**:
1. Wait for terminal to fully load (10-15 seconds)
2. Click on the terminal area to focus
3. Type: `echo "Hello World"`
4. Press Enter
5. Wait 3 seconds for output

**Expected Results**:
- Command appears as you type
- After pressing Enter, see either:
  - The command echo in terminal, OR
  - "Hello World" output, OR
  - Shell prompt returns

**Pass Criteria**: ✅ Text appears in terminal and command is processed
**Fail Criteria**: ❌ No text appears or command is not processed

---

### Test 1.2: Special Characters
**Objective**: Verify special characters work correctly

**Steps**:
1. Focus terminal
2. Test each character sequence:
   - `ls -la` (space and dash)
   - `echo "test@example.com"` (email symbols)
   - `echo 'single quotes'` (single quotes)
   - `echo $HOME` (environment variable)
3. Press Enter after each

**Expected Results**: All characters appear and commands execute

---

### Test 1.3: Control Characters
**Objective**: Verify control characters work

**Steps**:
1. Type: `cat` and press Enter
2. Type some text
3. Press Ctrl+C to interrupt
4. Verify prompt returns

**Expected Results**: Control characters processed correctly

## Test Suite 2: Multi-Terminal Scenarios

### Test 2.1: Rapid Input Switching
**Objective**: Test input handling with quick focus changes

**Steps**:
1. Click terminal to focus
2. Type: `echo "test1"`
3. Quickly click outside terminal then back
4. Continue typing: ` && echo "test2"`
5. Press Enter

**Expected Results**: Complete command executes correctly

---

### Test 2.2: Session Creation and Input
**Objective**: Test input after creating new sessions

**Steps**:
1. In current terminal, type: `echo "original session"`
2. If application supports multiple terminals, create new session
3. In new session, immediately type: `echo "new session"`
4. Switch between sessions and verify input routing

**Expected Results**: Input goes to correct session

## Test Suite 3: Focus Management

### Test 3.1: Click-to-Focus
**Objective**: Verify clicking activates input

**Steps**:
1. Click outside terminal area
2. Try typing (should not appear)
3. Click on terminal
4. Type: `echo "focus test"`
5. Press Enter

**Expected Results**: Input only works after clicking terminal

---

### Test 3.2: Multiple Click Areas
**Objective**: Test different clickable areas

**Test each area**:
- Terminal text area
- Terminal border
- Terminal container
- Terminal wrapper (if visible)

**Steps for each**:
1. Click outside terminal
2. Click test area
3. Type test text
4. Verify input works

## Test Suite 4: WebSocket and Connection

### Test 4.1: Page Refresh Input
**Objective**: Test input after page reload

**Steps**:
1. Type and execute a command successfully
2. Refresh the page (F5)
3. Wait for full reload (15 seconds)
4. Try typing immediately: `echo "after refresh"`
5. Press Enter

**Expected Results**: Input works after page refresh

---

### Test 4.2: Network Simulation
**Objective**: Test reconnection scenarios

**Steps**:
1. Open Developer Tools → Network tab
2. Type command: `echo "before disconnect"`
3. In Network tab, select "Offline" mode
4. Wait 5 seconds
5. Re-enable network
6. Wait for reconnection
7. Type: `echo "after reconnect"`

**Expected Results**: Input works after reconnection

## Test Suite 5: Edge Cases

### Test 5.1: Rapid Typing
**Objective**: Test fast input handling

**Steps**:
1. Focus terminal
2. Type very quickly: `echo "rapid typing test with lots of characters"`
3. Press Enter immediately
4. Repeat 3 times rapidly

**Expected Results**: All input captured correctly

---

### Test 5.2: Long Commands
**Objective**: Test handling of long input

**Steps**:
1. Type long command (200+ characters):
   ```bash
   echo "This is a very long command that tests whether the terminal input can handle extended text without dropping characters or causing issues with the input buffer management system"
   ```
2. Press Enter

**Expected Results**: Complete command processes correctly

---

### Test 5.3: Copy-Paste
**Objective**: Test paste functionality

**Steps**:
1. Copy text: `echo "pasted content"`
2. Focus terminal
3. Paste (Ctrl+V or Cmd+V)
4. Press Enter

**Expected Results**: Pasted content appears and executes

## Test Suite 6: Terminal Recreation

### Test 6.1: Container Recreation
**Objective**: Test input after container changes

**Steps**:
1. Successfully input a command
2. If possible, trigger terminal recreation (resize window significantly)
3. Wait for stabilization
4. Try input again: `echo "after recreation"`

**Expected Results**: Input works after recreation

## Error Scenarios to Test

### Error Test 1: Server Restart
1. Start terminal application
2. Test input works
3. Stop server process
4. Restart server
5. Refresh browser
6. Test input again

### Error Test 2: Invalid Input
1. Try typing extremely long input (1000+ chars)
2. Try binary characters (copy from binary file)
3. Try rapid key mashing
4. Verify terminal remains functional

## Console Monitoring

While testing, monitor browser console for these key events:

**Good Indicators**:
- "Input:" followed by typed characters
- "sendData" function calls
- "WebSocket connected" messages
- "Terminal marked as ready"

**Warning Signs**:
- "sendData not available" errors
- WebSocket connection failures
- "Terminal not ready" warnings
- JavaScript errors

## Success Criteria Summary

### Critical Must-Pass Tests
1. ✅ Basic single command input and execution
2. ✅ Terminal focus via clicking
3. ✅ Input routing to correct session
4. ✅ WebSocket reconnection maintains input

### Important Should-Pass Tests
1. ✅ Special characters and control sequences
2. ✅ Rapid input handling
3. ✅ Copy-paste functionality
4. ✅ Input after page refresh

### Nice-to-Have Tests
1. ✅ Multiple terminal session switching
2. ✅ Terminal recreation recovery
3. ✅ Network interruption handling

## Reporting Results

### For Each Test
Document:
- Test name and objective
- Steps performed
- Actual results
- Pass/Fail status
- Screenshots of any failures
- Browser console logs if issues occur

### Overall Assessment
- Count total tests: ___
- Count passed tests: ___
- Success rate: ___%
- Critical issues found: ___
- Recommendations for fixes: ___

## Quick Smoke Test (5 minutes)

If time is limited, run this abbreviated test:

1. **Basic Input** (1 min):
   - Type `echo "hello"` and press Enter
   - Verify text appears

2. **Focus Test** (1 min):
   - Click outside, then click terminal
   - Type command and verify it works

3. **Refresh Test** (2 min):
   - Refresh page, wait for load
   - Try typing immediately

4. **Special Characters** (1 min):
   - Type `ls -la && echo "done"`
   - Verify complex command works

**Pass Criteria**: All 4 tests must pass for basic functionality confirmation.