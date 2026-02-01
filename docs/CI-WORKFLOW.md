# Continuous Integrity (CI) Workflow Guide

## Overview
This project uses GitHub Actions for automated continuous integration and quality assurance. The CI pipeline enforces code quality, type safety, security, and functionality across all commits and pull requests.

## Pipeline Stages

### Stage 1: Lint & Type Check
**Runs on**: Node 18.x and 20.x  
**Purpose**: Ensure code style consistency and type safety

- **TypeScript Type Checking** (`tsc --noEmit`)
  - Validates all `.ts` and `.tsx` files for type correctness
  - Prevents runtime type errors
  
- **ESLint** (`npm run lint`)
  - Enforces code style rules
  - Detects potential bugs and anti-patterns
  - Configuration: `.eslintrc.json`
  
- **Prettier** (`npm run format`)
  - Checks code formatting consistency
  - Auto-fixable via `npm run format:fix`
  - Configuration: `.prettierrc.json`

### Stage 2: Security & Dependency Audit
**Runs on**: Node 18.x  
**Purpose**: Identify vulnerabilities and outdated packages

- **npm audit**
  - Scans dependencies for known CVEs
  - Alerts on moderate and high severity issues
  - Can auto-fix with `npm audit fix`

### Stage 3: Unit & Integration Tests
**Runs on**: Node 18.x and 20.x  
**Depends on**: Lint & Type Check passing

- **Vitest** (`npm run test`)
  - Runs all test files in `tests/` directory
  - Unit tests for cryptographic functions
  - Integration tests for complete workflows
  - Configuration: `vitest.config.ts`

- **Coverage Report**
  - Generates HTML coverage report
  - Enforces thresholds:
    - Lines: 70%
    - Functions: 70%
    - Branches: 60%
    - Statements: 70%
  - Uploads to Codecov (optional)
  - Artifacts stored for 30 days

### Stage 4: Build Verification
**Runs on**: Node 18.x  
**Depends on**: Tests and Security audit passing

- **Vite Build** (`npm run build`)
  - Compiles TypeScript and React code
  - Bundles assets for production
  - Verifies `dist/` directory is created
  - Uploads artifacts (7-day retention)

### Stage 5: CI Status Summary
**Runs on**: Final check  
**Status**: Shows overall pipeline health

- Aggregates results from all stages
- Fails if any critical stage fails
- Provides clear success/failure message

## Running Locally

### Prerequisites
```bash
node --version  # Should be 18.x or 20.x
npm --version   # Should be 8.0+
```

### Install Dependencies
```bash
npm install
```

### Run Tests
```bash
# Run once
npm run test

# Watch mode
npm run test:watch

# With coverage
npm run test:coverage
```

### Lint & Format
```bash
# Check formatting
npm run format

# Auto-fix formatting
npm run format:fix

# Check linting
npm run lint

# Type check
npm run type-check
```

### Build
```bash
npm run build
```

## Configuration Files

### `.eslintrc.json`
ESLint configuration for code quality rules. Extends `eslint:recommended` with TypeScript support.

### `.prettierrc.json`
Prettier configuration for code formatting. Key settings:
- Semi-colons: enabled
- Single quotes: enabled
- Print width: 100 characters
- Tab width: 2 spaces

### `vitest.config.ts`
Vitest configuration for unit testing:
- Environment: jsdom (for DOM APIs in tests)
- Coverage provider: v8
- Includes: `src/**/*.ts`, `services/**/*.ts`
- Excludes: node_modules, tests, spec files

### `.github/workflows/ci.yml`
GitHub Actions workflow definition. Triggers on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches

## Test Suite Structure

### `tests/cryptoService.test.ts`
Comprehensive tests covering:

**Key Generation**
- Valid RSA-2048 key pair generation
- Unique keys per call
- JSON-encoded base64 format

**Certificates**
- Certificate creation with required fields
- 1-year expiry window
- Issuer chain support
- Unique serial numbers

**Hashing**
- SHA-256 deterministic hashing
- Different inputs produce different hashes
- Handle empty and large inputs

**Digital Signatures**
- RSA-PSS signing and verification
- Detect tampered data
- Reject signatures from wrong keys
- RSA-PSS randomness (different sigs for same data)

**Hybrid Encryption**
- RSA-OAEP + AES-GCM encryption
- Decryption with correct key
- Fail gracefully with wrong key
- Handle large data (50KB+)

**Password-Based Encryption**
- PBKDF2 + AES-GCM protection
- PBKDF2 salt randomness
- Support special characters in passwords

**Identity Bundles**
- Export identity with password protection
- Import and restore identity
- Fail on wrong password

**Certificate Validity**
- Check expiry dates
- Detect revocation
- Validate before use

**OCSP/CRL**
- Revoke/unrevoke serials
- Check revocation status
- List CRL entries

**Integration Tests**
- End-to-end secure communication flow
- Vault persistence and restoration
- Certificate chain validation
- Medical report signing and encryption

## GitHub Actions Status Checks

### Required Checks (must pass to merge)
1. `lint-and-typecheck` — Code quality and types
2. `test` — All tests pass with coverage
3. `build` — Production build succeeds

### Optional/Warning Checks
- `security` — Dependency audit (continue-on-error)
- `ci-status` — Overall pipeline summary

## Troubleshooting

### Tests Failing Locally
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Run tests with detailed output
npm run test -- --reporter=verbose
```

### Type Check Errors
```bash
npm run type-check
```

### Lint Errors
```bash
# Show all linting issues
npm run lint

# Auto-fix what you can
npm run format:fix
```

### Build Failures
```bash
npm run build
# Check dist/ directory exists
ls -la dist/
```

### Coverage Below Threshold
```bash
npm run test:coverage
# Review coverage/coverage-final.json or coverage/index.html
open coverage/index.html
```

## Best Practices

1. **Write tests for crypto functions** — Every new cipher, signature, or hash function should have unit and integration tests.

2. **Run CI locally before pushing**
   ```bash
   npm run type-check && npm run lint && npm run test && npm run build
   ```

3. **Keep dependencies up to date**
   ```bash
   npm outdated
   npm update
   npm audit fix
   ```

4. **Use meaningful commit messages**
   ```
   fix: resolve decryption key mismatch
   test: add coverage for PKCS#12 export
   chore: update vitest to 1.2.0
   ```

5. **Enforce pre-commit hooks** (optional)
   ```bash
   npm install husky lint-staged --save-dev
   npx husky install
   ```

## Adding New Tests

Create a new test file in `tests/` following the pattern:

```typescript
import { describe, it, expect, beforeAll } from 'vitest';
import { functionToTest } from '../services/myService';

describe('My Feature', () => {
  it('should do something specific', async () => {
    const result = await functionToTest('input');
    expect(result).toBe('expected output');
  });
});
```

## CI/CD Metrics

- **Build time**: ~2-3 minutes (varies by environment)
- **Coverage target**: 70% lines, functions, statements; 60% branches
- **Node versions tested**: 18.x, 20.x
- **Operating system**: Linux (ubuntu-latest)

## Related Documentation
- [Crypto Report](./crypto-report.md) — Detailed cryptographic features and security analysis
- GitHub Actions Docs: https://docs.github.com/en/actions
- Vitest Docs: https://vitest.dev
- ESLint Docs: https://eslint.org
- Prettier Docs: https://prettier.io
