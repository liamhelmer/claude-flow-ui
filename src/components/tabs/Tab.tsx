'use client';

import { cn } from '@/lib/utils';
import type { TabProps } from '@/types';

export default function Tab({ 
  title, 
  isActive, 
  onSelect, 
  onClose, 
  closable = true 
}: TabProps) {
  const handleClose = (e: React.MouseEvent) => {
    e.stopPropagation();
    onClose();
  };

  return (
    <div
      className={cn(
        'tab-button group relative flex items-center gap-2 min-w-0',
        'border-b-2 transition-all duration-200',
        isActive 
          ? 'tab-button-active border-blue-500' 
          : 'tab-button-inactive border-transparent hover:border-gray-600'
      )}
      onClick={onSelect}
    >
      <span className="truncate text-sm font-medium">{title}</span>
      
      {closable && (
        <button
          onClick={handleClose}
          className={cn(
            'flex-shrink-0 w-4 h-4 rounded transition-colors',
            'flex items-center justify-center text-xs',
            isActive 
              ? 'hover:bg-gray-200 text-gray-600 hover:text-gray-800' 
              : 'hover:bg-gray-600 text-gray-400 hover:text-gray-200'
          )}
          aria-label={`Close ${title}`}
        >
          ×
        </button>
      )}
      
      {/* Active indicator */}
      {isActive && (
        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
      )}
    </div>
  );
}