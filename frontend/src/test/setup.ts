import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// React Testing Library doesn't auto-cleanup between tests outside of a
// Jest environment, so tests would otherwise leak DOM nodes across files.
afterEach(() => {
  cleanup();
});
