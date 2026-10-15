// Default build: no legacy security UI (its commands are not compiled in).
import type { LegacyRegistry } from './types';

const registry: LegacyRegistry = {
  sections: [],
  Provider: ({ children }) => <>{children}</>,
  Overlay: () => null,
};

export default registry;
