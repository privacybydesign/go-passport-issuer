// The /vitest entrypoint registers the jest-dom matchers on vitest's `expect`.
// The bare '@testing-library/jest-dom' import expects a Jest global instead and
// throws under vitest unless globals are enabled.
import '@testing-library/jest-dom/vitest';
