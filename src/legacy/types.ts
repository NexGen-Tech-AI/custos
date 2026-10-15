// The legacy security UI plugs into the app shell through this interface.
// `@legacy` resolves to ./disabled.tsx (default) or ./security.tsx
// (VITE_LEGACY_SECURITY=1, with the src-tauri feature "legacy-security").
import type { FC, ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';

export interface ExtraSection {
  id: string;
  label: string;
  icon: LucideIcon;
  render: () => ReactNode;
}

export interface LegacyRegistry {
  sections: ExtraSection[];
  /** Context providers the legacy sections need. */
  Provider: FC<{ children: ReactNode }>;
  /** UI drawn over every section (the floating scan indicator). */
  Overlay: FC<{ activeSection: string; onOpenSection: (id: string) => void }>;
}
