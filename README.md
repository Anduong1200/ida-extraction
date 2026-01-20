# HoloGuard

**Malware Detection Pipeline using Heterogeneous Graph Neural Networks**

## Overview

HoloGuard is a research-grade malware detection system that processes dynamic analysis logs (Cuckoo Sandbox) and uses Graph Neural Networks for classification.

## Quick Start

```bash
# Manual Mode (Batch JSON Export)
python main.py manual --input samples.txt --output ./exports

# ML Mode (Full Pipeline)
python main.py ml --input report.json --model model.pt
```

## Deployment Modes

### 1. Manual Mode (Massive Batch Export)

Process a list of Cuckoo reports and export structured JSON.  
**No ML dependencies required.**

```bash
# Create input list
echo "path/to/report1.json" > samples.txt
echo "path/to/report2.json" >> samples.txt

# Run
python main.py manual -i samples.txt -o ./exports
```

**Output:** `exports/{name}_parsed.json` for each input.

### 2. ML Mode (Graph Neural Network)

Full pipeline: Parse → Graph → Prune → H-GraphSAGE → Prediction.  
**Requires:** `torch`, `torch_geometric`, `networkx`

```bash
pip install torch torch_geometric networkx

python main.py ml -i report.json -m trained.pt -o result.json
```

## Project Structure

```
├── main.py                 # Entry point (Manual/ML modes)
├── cuckoo_parser.py        # Parse Cuckoo JSON reports
├── build_hetero_graph.py   # Construct HeteroData
├── graph_pruning.py        # Node-Centric Pruning (NCP)
├── models/
│   └── h_graphsage.py      # Heterogeneous GraphSAGE
├── generate_synthetic_cuckoo.py  # Test data generator
└── sample_export.json      # Example output
```

## Graph Schema

| Node Type | Description |
|-----------|-------------|
| Process   | Running processes (PID, Name) |
| API       | System API calls |
| File      | File system interactions |
| Network   | Network connections (IP, Domain) |
| Registry  | Registry modifications |

| Edge Type | Relationship |
|-----------|--------------|
| spawn     | Process → Process |
| call      | Process → API |
| access    | API → File |
| connect   | API → Network |
| modify    | API → Registry |
| next      | API → API (sequence) |

## Requirements

**Manual Mode:** Python 3.8+

**ML Mode:**
```bash
pip install torch torch_geometric networkx tqdm
```

## License

MIT
