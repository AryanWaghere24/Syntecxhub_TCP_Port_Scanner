# Contributing to CyberEye

Thank you for your interest in contributing to CyberEye! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and professional
- No harassment or discrimination
- Constructive feedback only
- Respect intellectual property

## How to Contribute

### Reporting Bugs

1. **Check existing issues** - Ensure the bug hasn't been reported
2. **Provide details:**
   - Python version
   - Operating system
   - Exact command that failed
   - Error message/traceback
   - Expected vs actual behavior

3. **Create an issue** with the template:
```
**Bug Description:**
[Clear description]

**Steps to Reproduce:**
1. 
2. 
3. 

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happens]

**Environment:**
- Python: 3.x
- OS: [Windows/macOS/Linux]
- CyberEye version: [version]

**Error Log:**
[Paste error message here]
```

### Suggesting Enhancements

1. **Check existing issues** - Avoid duplicates
2. **Describe the enhancement:**
   - Use case
   - Expected behavior
   - Why it would be useful
   - Possible implementation

3. **Create an enhancement issue**

### Submitting Code

#### Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/yourusername/CyberEye.git
cd CyberEye
```

#### Create a Branch

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Or for bugfixes
git checkout -b bugfix/issue-description
```

#### Make Changes

1. Follow the existing code style
2. Add comments for complex logic
3. Maintain backward compatibility
4. Test thoroughly

#### Code Style Guidelines

```python
# Follow PEP 8
# Use type hints where possible
def scan_port(self, port: int) -> PortStatus:
    """Clear docstring"""
    
# Use meaningful variable names
open_ports = []  # Good
op = []          # Bad

# Comment complex logic
# Calculate TTL by analyzing ping response
ttl = int(ttl_value)

# Use f-strings for formatting
print(f"Port {port} is {status}")
```

#### Commit Messages

```
# Good commit messages
git commit -m "Add OS detection for TTL 120 (Google servers)"
git commit -m "Fix: Handle socket timeout gracefully"
git commit -m "Refactor: Simplify banner parsing logic"

# Bad commit messages
git commit -m "fix stuff"
git commit -m "updates"
```

#### Testing

Before submitting:

```bash
# Test basic functionality
python CyberEye.py -h
python CyberEye.py -t 8.8.8.8 -p 80,443

# Test with different options
python CyberEye.py -t 127.0.0.1 -r 1-100
python CyberEye.py -t 8.8.8.8 --os-detect
python CyberEye.py -t 8.8.8.8 -p 80,443 --json
```

#### Submit Pull Request

1. Push to your fork:
```bash
git push origin feature/your-feature-name
```

2. Create PR on GitHub with:
   - Clear title
   - Description of changes
   - Reason for changes
   - Testing performed
   - Related issues

3. PR Template:
```
## Description
[Brief description of changes]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Improvement
- [ ] Documentation

## Changes Made
- [Change 1]
- [Change 2]

## Testing Performed
[How did you test this?]

## Related Issues
Closes #[issue number]

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed the code
- [ ] Added comments for complex logic
- [ ] Tested thoroughly
- [ ] No breaking changes
```

## Development Setup

### Requirements
- Python 3.6+
- Git

### Setup

```bash
# Clone repository
git clone https://github.com/yourusername/CyberEye.git
cd CyberEye

# Test it works
python CyberEye.py -h
```

### Project Structure

```
CyberEye/
├── CyberEye.py          # Main application
├── README.md            # Documentation
├── LICENSE              # MIT License
├── CONTRIBUTING.md      # This file
└── tests/               # Test files
    ├── test_scanner.py
    ├── test_os_detect.py
    └── test_edge_cases.py
```

## Areas for Contribution

### Bug Fixes
- Fix OS detection issues
- Improve error handling
- Handle edge cases

### Features
- SYN scanning support
- CIDR notation support
- Service version database expansion
- Web UI dashboard
- Configuration files
- Distributed scanning

### Documentation
- Improve README
- Add tutorials
- Create video guides
- Expand troubleshooting
- Add code examples

### Testing
- Unit tests
- Integration tests
- Performance tests
- Edge case handling

### Performance
- Optimize socket operations
- Improve threading efficiency
- Reduce memory usage
- Faster port scanning

## Review Process

1. **Code Review** - Maintainers review your PR
2. **Feedback** - May request changes
3. **Testing** - Code will be tested
4. **Merge** - Approved PRs will be merged

## Legal

By contributing, you agree that:
- Your contributions are original
- You have rights to your contribution
- Code follows MIT License
- No plagiarism or stolen code

## Questions?

- Check existing issues
- Read documentation
- Create a discussion issue
- Contact maintainers

## Recognition

Contributors will be:
- Thanked in commit messages
- Listed in CONTRIBUTORS.md
- Credited in releases

## Final Notes

- Start with small contributions
- Be patient with review process
- Communicate clearly
- Help others too!

Thank you for making CyberEye better! 🚀
