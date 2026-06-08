# 🔗 Chainsaw Integration Guide

## Architecture

Windows System → Event Logs → Chainsaw + Sigma → Detections → Response

## Quick Integration

```bash
# 1. Copy our rules to chainsaw
cp -r rules/sigma/ /path/to/chainsaw/

# 2. Run hunt
chainsaw hunt /path/to/logs -s rules/sigma/

# 3. Analyze results
chainsaw hunt /path/to/logs -s rules/sigma/ -o json | jq '.'
```

## Real-World Workflow
## Real-World Workflow
## Performance

```bash
# Fast hunt (specific rule)
chainsaw hunt logs/ -s rules/sigma/office_macros.yml

# Comprehensive hunt (all rules)
chainsaw hunt logs/ -s rules/sigma/ --verbose

# With time filter
chainsaw hunt logs/ --start "2026-06-08 10:00:00" --end "2026-06-08 12:00:00"
```

## Troubleshooting

- No detections? Check log format is .evtx
- False positives? Review rule syntax
- Slow? Use time range filters
- Missing events? Verify Windows logging enabled

See CHAINSAW_SETUP.md for detailed setup instructions.
