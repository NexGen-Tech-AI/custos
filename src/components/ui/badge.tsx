import React from 'react';
import { cn } from '@/lib/utils';

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'secondary' | 'outline';
}

function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2",
        {
          'border-transparent bg-gray-700 text-white hover:bg-gray-600': variant === 'default',
          'border-transparent bg-gray-800 text-white hover:bg-gray-700': variant === 'secondary',
          'border-gray-600 text-white': variant === 'outline',
        },
        className
      )}
      {...props}
    />
  );
}

export { Badge };
