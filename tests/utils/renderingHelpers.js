/**
 * Component Rendering Helpers for Integration Tests
 * 
 * Provides utilities for proper component rendering, waiting for state changes,
 * and handling async component behavior in integration tests.
 */

import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

/**
 * Enhanced component renderer with built-in state management and cleanup
 */
export class ComponentRenderer {
  constructor() {
    this.renderedComponents = new Set();
    this.cleanupFunctions = new Set();
    this.activeTimers = new Set();
  }

  /**
   * Render component with automatic cleanup tracking
   */
  renderWithCleanup(component, options = {}) {
    const result = render(component, options);
    
    this.renderedComponents.add(result);
    this.cleanupFunctions.add(() => {
      if (result.unmount) {
        try {
          result.unmount();
        } catch (error) {
          console.warn('Cleanup error during unmount:', error);
        }
      }
    });

    return result;
  }

  /**
   * Wait for component to reach specific state with timeout
   */
  async waitForComponentState(selector, expectedState, options = {}) {
    const { timeout = 3000, interval = 100, selectorType = 'testId' } = options;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      let element;
      
      try {
        switch (selectorType) {
          case 'testId':
            element = screen.queryByTestId(selector);
            break;
          case 'role':
            element = screen.queryByRole(selector);
            break;
          case 'text':
            element = screen.queryByText(selector);
            break;
          case 'labelText':
            element = screen.queryByLabelText(selector);
            break;
          default:
            element = screen.queryByTestId(selector);
        }

        if (this.checkElementState(element, expectedState)) {
          return element;
        }
      } catch (error) {
        // Continue waiting if element not found
      }

      await this.sleep(interval);
    }

    throw new Error(`Component ${selector} did not reach expected state ${JSON.stringify(expectedState)} within ${timeout}ms`);
  }

  /**
   * Check if element matches expected state
   */
  checkElementState(element, expectedState) {
    if (!element && expectedState.exists === false) {
      return true;
    }
    
    if (!element && expectedState.exists !== false) {
      return false;
    }

    // Check visibility
    if (expectedState.visible !== undefined) {
      const isVisible = element.style.display !== 'none' && 
                       element.style.visibility !== 'hidden' &&
                       element.offsetParent !== null;
      if (isVisible !== expectedState.visible) {
        return false;
      }
    }

    // Check text content
    if (expectedState.textContent !== undefined) {
      if (!element.textContent.includes(expectedState.textContent)) {
        return false;
      }
    }

    // Check attributes
    if (expectedState.attributes) {
      for (const [attr, value] of Object.entries(expectedState.attributes)) {
        if (element.getAttribute(attr) !== value) {
          return false;
        }
      }
    }

    // Check classes
    if (expectedState.classes) {
      for (const className of expectedState.classes) {
        if (!element.classList.contains(className)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Wait for async component effects to complete
   */
  async waitForAsyncEffects(timeout = 2000) {
    await act(async () => {
      await this.sleep(50); // Allow effects to start
    });

    // Wait for any pending promises to resolve
    await waitFor(() => {
      // This forces React to flush any pending effects
      expect(document.body).toBeInTheDocument();
    }, { timeout });
  }

  /**
   * Enhanced user interaction with proper timing
   */
  async performUserInteraction(action, options = {}) {
    const { waitBefore = 10, waitAfter = 50, retries = 3 } = options;
    
    await this.sleep(waitBefore);
    
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        await act(async () => {
          await action();
        });
        break;
      } catch (error) {
        if (attempt === retries - 1) {
          throw error;
        }
        await this.sleep(100);
      }
    }
    
    await this.sleep(waitAfter);
    await this.waitForAsyncEffects();
  }

  /**
   * Click element with proper waiting
   */
  async clickElement(selector, options = {}) {
    const element = await this.waitForComponentState(selector, { exists: true }, options);
    const user = userEvent.setup();

    await this.performUserInteraction(async () => {
      await user.click(element);
    });

    return element;
  }

  /**
   * Type text with proper timing
   */
  async typeText(selector, text, options = {}) {
    const element = await this.waitForComponentState(selector, { exists: true }, options);
    const user = userEvent.setup();

    await this.performUserInteraction(async () => {
      await user.type(element, text);
    });

    return element;
  }

  /**
   * Wait for component to render and be interactive
   */
  async waitForInteractiveComponent(selector, options = {}) {
    const { timeout = 3000 } = options;
    
    await waitFor(async () => {
      const element = await this.waitForComponentState(selector, { 
        exists: true, 
        visible: true 
      }, { ...options, timeout: timeout / 3 });
      
      expect(element).toBeInTheDocument();
    }, { timeout });

    // Additional wait for component to be fully interactive
    await this.waitForAsyncEffects();
  }

  /**
   * Wait for multiple components to render
   */
  async waitForMultipleComponents(selectors, options = {}) {
    const promises = selectors.map(selector => 
      this.waitForInteractiveComponent(selector, options)
    );
    
    await Promise.all(promises);
  }

  /**
   * Check component accessibility
   */
  checkAccessibility(component) {
    const accessibilityIssues = [];

    // Check for ARIA labels
    const interactiveElements = component.querySelectorAll('button, input, select, textarea, [role="button"], [role="tab"]');
    interactiveElements.forEach(element => {
      const hasLabel = element.hasAttribute('aria-label') || 
                      element.hasAttribute('aria-labelledby') ||
                      element.textContent.trim() !== '';
      
      if (!hasLabel) {
        accessibilityIssues.push(`Interactive element missing label: ${element.tagName}`);
      }
    });

    // Check for proper headings hierarchy
    const headings = component.querySelectorAll('h1, h2, h3, h4, h5, h6');
    let prevLevel = 0;
    headings.forEach(heading => {
      const level = parseInt(heading.tagName[1]);
      if (level > prevLevel + 1) {
        accessibilityIssues.push(`Heading level jump: ${heading.tagName} after h${prevLevel}`);
      }
      prevLevel = level;
    });

    return accessibilityIssues;
  }

  /**
   * Utility sleep function
   */
  sleep(ms) {
    return new Promise(resolve => {
      const timeoutId = setTimeout(resolve, ms);
      this.activeTimers.add(timeoutId);
    });
  }

  /**
   * Clean up all rendered components and timers
   */
  async cleanup() {
    // Clear timers
    this.activeTimers.forEach(timerId => clearTimeout(timerId));
    this.activeTimers.clear();

    // Clean up components
    for (const cleanupFn of this.cleanupFunctions) {
      try {
        await cleanupFn();
      } catch (error) {
        console.warn('Error during cleanup:', error);
      }
    }
    
    this.cleanupFunctions.clear();
    this.renderedComponents.clear();
  }
}

/**
 * Component Testing Wrapper with providers
 */
export const createTestWrapper = (providers = {}) => {
  const { store, router, theme } = providers;
  
  return function TestWrapper({ children }) {
    let wrapped = children;
    
    // Add providers in reverse order so they wrap correctly
    if (theme) {
      wrapped = React.createElement(theme, {}, wrapped);
    }
    
    if (router) {
      wrapped = React.createElement(router, {}, wrapped);
    }
    
    if (store) {
      wrapped = React.createElement(store, {}, wrapped);
    }
    
    return wrapped;
  };
};

/**
 * Enhanced test environment setup
 */
export const setupTestEnvironment = () => {
  const renderer = new ComponentRenderer();
  
  return {
    renderer,
    
    // Convenience methods
    render: (component, options) => renderer.renderWithCleanup(component, options),
    waitFor: (selector, state, options) => renderer.waitForComponentState(selector, state, options),
    click: (selector, options) => renderer.clickElement(selector, options),
    type: (selector, text, options) => renderer.typeText(selector, text, options),
    waitForReady: (selector, options) => renderer.waitForInteractiveComponent(selector, options),
    
    // Cleanup
    cleanup: () => renderer.cleanup(),
  };
};

/**
 * Specialized integration test renderer
 */
export class IntegrationTestRenderer extends ComponentRenderer {
  constructor() {
    super();
    this.mockState = new Map();
    this.stateChangeCallbacks = new Map();
  }

  /**
   * Set mock state for components
   */
  setMockState(key, value) {
    const oldValue = this.mockState.get(key);
    this.mockState.set(key, value);
    
    // Notify state change callbacks
    const callbacks = this.stateChangeCallbacks.get(key) || [];
    callbacks.forEach(callback => {
      try {
        callback(value, oldValue);
      } catch (error) {
        console.error(`Error in state change callback for ${key}:`, error);
      }
    });
  }

  /**
   * Subscribe to mock state changes
   */
  onStateChange(key, callback) {
    if (!this.stateChangeCallbacks.has(key)) {
      this.stateChangeCallbacks.set(key, []);
    }
    this.stateChangeCallbacks.get(key).push(callback);
  }

  /**
   * Get mock state
   */
  getMockState(key) {
    return this.mockState.get(key);
  }

  /**
   * Render component with mock state injection
   */
  renderWithMockState(component, initialState = {}) {
    // Set initial state
    Object.entries(initialState).forEach(([key, value]) => {
      this.setMockState(key, value);
    });

    return this.renderWithCleanup(component);
  }
}

// Default export
export default {
  ComponentRenderer,
  IntegrationTestRenderer,
  createTestWrapper,
  setupTestEnvironment,
};