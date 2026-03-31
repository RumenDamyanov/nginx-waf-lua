# Contributing to nginx-waf-lua

Thank you for your interest in contributing! This project is in early experimental stages.

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use a clear, descriptive title
3. Include steps to reproduce, expected vs actual behavior, and relevant logs

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `make test`
5. Commit with clear messages
6. Open a pull request

#### Code Standards

- Follow Lua best practices
- Use OpenResty coding conventions
- Write tests with Test::Nginx or busted
- Document public APIs
- Avoid blocking operations

### Commit Messages

Use clear, descriptive commit messages:

```
Add feed scheduler with cron support

- Implement per-feed cron schedules
- Add concurrent feed processing
- Handle overlapping runs gracefully
```

## Development Setup

See the README for build and development instructions.

## License

By contributing, you agree that your contributions will be licensed under the BSD 3-Clause License.
