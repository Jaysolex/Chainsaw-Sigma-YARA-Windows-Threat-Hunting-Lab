# Contributing to SOC Threat Hunting Playbook

Thank you for your interest in contributing! This project is built by the security community, for the security community.

## How to Contribute

### 1. Adding New Sigma Rules

**Before adding:**
- Test rule against sample Sysmon logs
- Verify no false positives
- Document false positive analysis
- Include MITRE ATT&CK mappings

**Files to create:**
- `rules/sigma/your_rule_name.yml`
- Update `docs/SIGMA_REFERENCE.md`
- Add example lab scenario if available

### 2. Adding New YARA Rules

**Before adding:**
- Test against benign files
- Test against confirmed malicious samples
- Document detection logic
- Include sample file analysis

**Files to create:**
- `rules/yara/your_rule_name.yar`
- Update `docs/YARA_REFERENCE.md`

### 3. Contributing Lab Examples

**Include:**
- Real Sysmon event data (anonymized)
- Screenshots of alerts
- Attack timeline
- Detection results
- Remediation steps

**Place in:**
- `examples/lab_[number]_[description].md`
- `examples/sysmon_events/` for raw data

### 4. Improving Documentation

- Fix typos and unclear explanations
- Add missing examples
- Clarify detection logic
- Improve playbook procedures

## Submission Process

1. Fork the repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Make changes and test thoroughly
4. Commit with clear messages: `git commit -m "Add: description"`
5. Push to branch: `git push origin feature/your-feature`
6. Open Pull Request

## Pull Request Guidelines

- Describe what was added and why
- Reference related issues
- Include before/after examples
- Test results (if applicable)

## Code of Conduct

- Be respectful and constructive
- Assume good intentions
- Provide helpful feedback
- No discrimination or harassment

## Questions?

- Open an issue with `[QUESTION]` tag
- Check existing discussions first
- Be specific about your question

Thank you for making this project better! 🙏
