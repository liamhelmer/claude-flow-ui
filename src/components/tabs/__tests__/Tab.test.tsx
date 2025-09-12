import React from 'react';
import { render, screen, fireEvent } from '../../../tests/test-utils';
import Tab from '../Tab';

describe('Tab Component', () => {
  const mockProps = {
    title: 'Test Tab',
    isActive: false,
    onSelect: jest.fn(),
    onClose: jest.fn(),
    closable: true,
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render tab with correct title', () => {
      render(<Tab {...mockProps} />);
      
      expect(screen.getByText('Test Tab')).toBeInTheDocument();
    });

    it('should apply correct base classes', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass(
        'group',
        'relative',
        'flex',
        'items-center',
        'gap-2',
        'min-w-0',
        'border-b-2',
        'transition-all',
        'duration-200'
      );
    });

    it('should show close button when closable is true', () => {
      render(<Tab {...mockProps} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      expect(closeButton).toBeInTheDocument();
      expect(closeButton).toHaveTextContent('×');
    });

    it('should not show close button when closable is false', () => {
      render(<Tab {...mockProps} closable={false} />);
      
      expect(screen.queryByRole('button', { name: 'Close Test Tab' })).not.toBeInTheDocument();
      expect(screen.queryByText('×')).not.toBeInTheDocument();
    });

    it('should default closable to true when not specified', () => {
      const propsWithoutClosable = {
        title: 'Test Tab',
        isActive: false,
        onSelect: jest.fn(),
        onClose: jest.fn(),
      };
      
      render(<Tab {...propsWithoutClosable} />);
      
      expect(screen.getByRole('button', { name: 'Close Test Tab' })).toBeInTheDocument();
    });
  });

  describe('Active State Styling', () => {
    it('should apply active styles when isActive is true', () => {
      render(<Tab {...mockProps} isActive={true} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass('tab-button-active', 'border-blue-500');
    });

    it('should apply inactive styles when isActive is false', () => {
      render(<Tab {...mockProps} isActive={false} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass('tab-button-inactive', 'border-transparent', 'hover:border-gray-600');
    });

    it('should show active indicator when active', () => {
      render(<Tab {...mockProps} isActive={true} />);
      
      const activeIndicator = document.querySelector('.absolute.bottom-0.left-0.right-0.h-0\\.5.bg-blue-500');
      expect(activeIndicator).toBeInTheDocument();
    });

    it('should not show active indicator when inactive', () => {
      render(<Tab {...mockProps} isActive={false} />);
      
      const activeIndicator = document.querySelector('.absolute.bottom-0.left-0.right-0.h-0\\.5.bg-blue-500');
      expect(activeIndicator).not.toBeInTheDocument();
    });
  });

  describe('Close Button Styling', () => {
    it('should apply correct styles to close button when active', () => {
      render(<Tab {...mockProps} isActive={true} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      expect(closeButton).toHaveClass(
        'flex-shrink-0',
        'w-4',
        'h-4',
        'rounded',
        'transition-colors',
        'flex',
        'items-center',
        'justify-center',
        'text-xs',
        'hover:bg-gray-200',
        'text-gray-600',
        'hover:text-gray-800'
      );
    });

    it('should apply correct styles to close button when inactive', () => {
      render(<Tab {...mockProps} isActive={false} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      expect(closeButton).toHaveClass(
        'hover:bg-gray-600',
        'text-gray-400',
        'hover:text-gray-200'
      );
    });
  });

  describe('Click Interactions', () => {
    it('should call onSelect when tab is clicked', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button') as HTMLElement;
      fireEvent.click(tabElement);
      
      expect(mockProps.onSelect).toHaveBeenCalledTimes(1);
    });

    it('should call onClose when close button is clicked', () => {
      render(<Tab {...mockProps} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      fireEvent.click(closeButton);
      
      expect(mockProps.onClose).toHaveBeenCalledTimes(1);
    });

    it('should stop propagation when close button is clicked', () => {
      render(<Tab {...mockProps} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      fireEvent.click(closeButton);
      
      // onClose should be called but onSelect should not be called due to stopPropagation
      expect(mockProps.onClose).toHaveBeenCalledTimes(1);
      expect(mockProps.onSelect).not.toHaveBeenCalled();
    });

    it('should handle multiple rapid clicks on tab', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button') as HTMLElement;
      
      fireEvent.click(tabElement);
      fireEvent.click(tabElement);
      fireEvent.click(tabElement);
      
      expect(mockProps.onSelect).toHaveBeenCalledTimes(3);
    });

    it('should handle multiple rapid clicks on close button', () => {
      render(<Tab {...mockProps} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      
      fireEvent.click(closeButton);
      fireEvent.click(closeButton);
      fireEvent.click(closeButton);
      
      expect(mockProps.onClose).toHaveBeenCalledTimes(3);
    });
  });

  describe('Text Content', () => {
    it('should display title with correct styling', () => {
      render(<Tab {...mockProps} />);
      
      const titleElement = screen.getByText('Test Tab');
      expect(titleElement).toHaveClass('truncate', 'text-sm', 'font-medium');
    });

    it('should handle long titles with truncation', () => {
      const longTitle = 'Very Long Tab Title That Should Be Truncated Because It Is Too Long To Display';
      
      render(<Tab {...mockProps} title={longTitle} />);
      
      const titleElement = screen.getByText(longTitle);
      expect(titleElement).toHaveClass('truncate');
    });

    it('should handle empty title', () => {
      render(<Tab {...mockProps} title="" />);
      
      // Should render without error
      const tabElement = document.querySelector('.tab-button');
      expect(tabElement).toBeInTheDocument();
    });

    it('should handle special characters in title', () => {
      const specialTitle = 'Tab & <Title> "With" \'Special\' Characters';
      
      render(<Tab {...mockProps} title={specialTitle} />);
      
      expect(screen.getByText(specialTitle)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA label for close button', () => {
      render(<Tab {...mockProps} title="My Tab" closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close My Tab' });
      expect(closeButton).toHaveAttribute('aria-label', 'Close My Tab');
    });

    it('should be keyboard accessible', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button') as HTMLElement;
      
      fireEvent.keyDown(tabElement, { key: 'Enter' });
      expect(mockProps.onSelect).toHaveBeenCalledTimes(1);
    });

    it('should handle keyboard navigation on close button', () => {
      render(<Tab {...mockProps} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      
      fireEvent.keyDown(closeButton, { key: 'Enter' });
      expect(mockProps.onClose).toHaveBeenCalledTimes(1);
    });

    it('should be focusable for keyboard navigation', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button') as HTMLElement;
      tabElement.focus();
      
      expect(document.activeElement).toBe(tabElement);
    });
  });

  describe('Hover States', () => {
    it('should have hover classes for inactive tabs', () => {
      render(<Tab {...mockProps} isActive={false} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass('hover:border-gray-600');
    });

    it('should have hover classes for close button', () => {
      render(<Tab {...mockProps} closable={true} />);
      
      const closeButton = screen.getByRole('button', { name: 'Close Test Tab' });
      expect(closeButton).toHaveClass('hover:bg-gray-600', 'hover:text-gray-200');
    });
  });

  describe('Props Edge Cases', () => {
    it('should handle undefined props gracefully', () => {
      const minimalProps = {
        title: 'Test',
        isActive: false,
        onSelect: jest.fn(),
        onClose: jest.fn(),
      };
      
      expect(() => render(<Tab {...minimalProps} />)).not.toThrow();
    });

    it('should handle boolean props correctly', () => {
      render(<Tab {...mockProps} isActive={true} closable={false} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass('tab-button-active');
      expect(screen.queryByText('×')).not.toBeInTheDocument();
    });
  });

  describe('Layout and Positioning', () => {
    it('should have correct flex layout', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass('flex', 'items-center', 'gap-2');
    });

    it('should have relative positioning for active indicator', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass('relative');
    });

    it('should handle min-width constraints', () => {
      render(<Tab {...mockProps} />);
      
      const tabElement = screen.getByText('Test Tab').closest('.tab-button');
      expect(tabElement).toHaveClass('min-w-0');
    });
  });

  describe('Performance', () => {
    it('should render efficiently with complex titles', () => {
      const complexTitle = '🚀 Terminal Session #1 (Production) - Active';
      
      const startTime = performance.now();
      render(<Tab {...mockProps} title={complexTitle} />);
      const endTime = performance.now();
      
      expect(endTime - startTime).toBeLessThan(50);
      expect(screen.getByText(complexTitle)).toBeInTheDocument();
    });
  });
});