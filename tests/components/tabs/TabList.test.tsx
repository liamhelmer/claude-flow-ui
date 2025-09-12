import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import TabList from '@/components/tabs/TabList';
import type { TerminalSession } from '@/types';

// Mock the Tab component since we're testing TabList specifically
jest.mock('@/components/tabs/Tab', () => {
  return function MockTab({ title, isActive, onSelect, onClose, closable }: any) {
    return (
      <div data-testid={`tab-${title}`}>
        <button 
          onClick={onSelect}
          className={isActive ? 'active-tab' : 'inactive-tab'}
        >
          {title}
        </button>
        {closable && (
          <button onClick={onClose} data-testid={`close-${title}`}>
            ×
          </button>
        )}
      </div>
    );
  };
});

describe('TabList', () => {
  const mockSessions: TerminalSession[] = [
    {
      id: 'session-1',
      name: 'Terminal 1',
      created: new Date(),
      lastActivity: new Date(),
    },
    {
      id: 'session-2',
      name: 'Terminal 2',
      created: new Date(),
      lastActivity: new Date(),
    },
    {
      id: 'session-3',
      name: 'Terminal 3',
      created: new Date(),
      lastActivity: new Date(),
    },
  ];

  const defaultProps = {
    sessions: mockSessions,
    activeSessionId: 'session-1',
    onSessionSelect: jest.fn(),
    onSessionClose: jest.fn(),
    onNewSession: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('renders all sessions as tabs', () => {
    render(<TabList {...defaultProps} />);

    expect(screen.getByTestId('tab-Terminal 1')).toBeInTheDocument();
    expect(screen.getByTestId('tab-Terminal 2')).toBeInTheDocument();
    expect(screen.getByTestId('tab-Terminal 3')).toBeInTheDocument();
  });

  it('renders new session button', () => {
    render(<TabList {...defaultProps} />);

    const newButton = screen.getByRole('button', { name: 'New terminal session' });
    expect(newButton).toBeInTheDocument();
    expect(newButton).toHaveTextContent('+');
  });

  it('calls onNewSession when new button is clicked', () => {
    render(<TabList {...defaultProps} />);

    const newButton = screen.getByRole('button', { name: 'New terminal session' });
    fireEvent.click(newButton);

    expect(defaultProps.onNewSession).toHaveBeenCalledTimes(1);
  });

  it('passes correct props to Tab components', () => {
    render(<TabList {...defaultProps} />);

    // Check active tab styling
    const activeTab = screen.getByText('Terminal 1');
    expect(activeTab).toHaveClass('active-tab');

    // Check inactive tab styling
    const inactiveTab = screen.getByText('Terminal 2');
    expect(inactiveTab).toHaveClass('inactive-tab');
  });

  it('makes tabs closable when there are multiple sessions', () => {
    render(<TabList {...defaultProps} />);

    // Should have close buttons for all tabs when multiple sessions exist
    expect(screen.getByTestId('close-Terminal 1')).toBeInTheDocument();
    expect(screen.getByTestId('close-Terminal 2')).toBeInTheDocument();
    expect(screen.getByTestId('close-Terminal 3')).toBeInTheDocument();
  });

  it('makes tabs not closable when there is only one session', () => {
    const singleSessionProps = {
      ...defaultProps,
      sessions: [mockSessions[0]],
    };

    render(<TabList {...singleSessionProps} />);

    // Should not have close button when only one session exists
    expect(screen.queryByTestId('close-Terminal 1')).not.toBeInTheDocument();
  });

  it('handles empty sessions array', () => {
    const emptyProps = {
      ...defaultProps,
      sessions: [],
      activeSessionId: null,
    };

    render(<TabList {...emptyProps} />);

    // Should still render the new session button
    expect(screen.getByRole('button', { name: 'New terminal session' })).toBeInTheDocument();

    // Should not render any tab components
    expect(screen.queryByTestId(/^tab-/)).not.toBeInTheDocument();
  });

  it('handles active session that does not exist in sessions', () => {
    const invalidActiveProps = {
      ...defaultProps,
      activeSessionId: 'non-existent-session',
    };

    render(<TabList {...invalidActiveProps} />);

    // Should not crash and should render all tabs
    expect(screen.getByTestId('tab-Terminal 1')).toBeInTheDocument();
    expect(screen.getByTestId('tab-Terminal 2')).toBeInTheDocument();
    expect(screen.getByTestId('tab-Terminal 3')).toBeInTheDocument();

    // All tabs should be inactive
    expect(screen.getByText('Terminal 1')).toHaveClass('inactive-tab');
    expect(screen.getByText('Terminal 2')).toHaveClass('inactive-tab');
    expect(screen.getByText('Terminal 3')).toHaveClass('inactive-tab');
  });

  it('applies custom className when provided', () => {
    const customClassName = 'custom-tab-list';
    render(<TabList {...defaultProps} className={customClassName} />);

    const tabListContainer = screen.getByRole('button', { name: 'New terminal session' }).parentElement;
    expect(tabListContainer).toHaveClass(customClassName);
  });

  it('calls onSessionSelect when tab is clicked', () => {
    render(<TabList {...defaultProps} />);

    const tab2Button = screen.getByText('Terminal 2');
    fireEvent.click(tab2Button);

    expect(defaultProps.onSessionSelect).toHaveBeenCalledWith('session-2');
  });

  it('calls onSessionClose when close button is clicked', () => {
    render(<TabList {...defaultProps} />);

    const closeButton = screen.getByTestId('close-Terminal 2');
    fireEvent.click(closeButton);

    expect(defaultProps.onSessionClose).toHaveBeenCalledWith('session-2');
  });

  it('renders tabs in scrollable container', () => {
    render(<TabList {...defaultProps} />);

    const tabsContainer = screen.getByTestId('tab-Terminal 1').parentElement;
    expect(tabsContainer).toHaveClass('overflow-x-auto');
    expect(tabsContainer).toHaveClass('scrollbar-thin');
    expect(tabsContainer).toHaveClass('scrollbar-thumb-gray-600');
  });

  it('handles long session names gracefully', () => {
    const longNameSessions: TerminalSession[] = [
      {
        id: 'session-long',
        name: 'Very Long Terminal Session Name That Might Overflow',
        created: new Date(),
        lastActivity: new Date(),
      },
    ];

    const longNameProps = {
      ...defaultProps,
      sessions: longNameSessions,
      activeSessionId: 'session-long',
    };

    render(<TabList {...longNameProps} />);

    expect(screen.getByTestId('tab-Very Long Terminal Session Name That Might Overflow')).toBeInTheDocument();
  });

  it('maintains flex layout for proper spacing', () => {
    render(<TabList {...defaultProps} />);

    const container = screen.getByRole('button', { name: 'New terminal session' }).parentElement;
    expect(container).toHaveClass('flex');
    expect(container).toHaveClass('items-center');

    const tabsSection = screen.getByTestId('tab-Terminal 1').parentElement;
    expect(tabsSection).toHaveClass('flex');
    expect(tabsSection).toHaveClass('flex-1');
  });

  it('applies correct styling to new session button', () => {
    render(<TabList {...defaultProps} />);

    const newButton = screen.getByRole('button', { name: 'New terminal session' });
    expect(newButton).toHaveClass('flex-shrink-0');
    expect(newButton).toHaveClass('px-3');
    expect(newButton).toHaveClass('py-2');
    expect(newButton).toHaveClass('text-sm');
    expect(newButton).toHaveClass('font-medium');
    expect(newButton).toHaveClass('border-l');
    expect(newButton).toHaveClass('border-gray-700');
  });

  it('handles null activeSessionId', () => {
    const nullActiveProps = {
      ...defaultProps,
      activeSessionId: null,
    };

    render(<TabList {...nullActiveProps} />);

    // All tabs should be inactive
    expect(screen.getByText('Terminal 1')).toHaveClass('inactive-tab');
    expect(screen.getByText('Terminal 2')).toHaveClass('inactive-tab');
    expect(screen.getByText('Terminal 3')).toHaveClass('inactive-tab');
  });

  it('handles rapid session creation and deletion', () => {
    const { rerender } = render(<TabList {...defaultProps} />);

    // Add a new session
    const newSessions = [...mockSessions, {
      id: 'session-4',
      name: 'Terminal 4',
      created: new Date(),
      lastActivity: new Date(),
    }];

    rerender(<TabList {...defaultProps} sessions={newSessions} />);
    expect(screen.getByTestId('tab-Terminal 4')).toBeInTheDocument();

    // Remove a session
    const reducedSessions = newSessions.slice(0, -1);
    rerender(<TabList {...defaultProps} sessions={reducedSessions} />);
    expect(screen.queryByTestId('tab-Terminal 4')).not.toBeInTheDocument();
  });
});