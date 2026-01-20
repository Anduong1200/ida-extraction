#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
HoloGuard - Malware Detection Pipeline
=======================================
Main entry point with two deployment modes:
1. MANUAL MODE: Batch process files -> JSON export (No ML)
2. ML MODE: Full pipeline with Heterogeneous GraphSAGE

Usage:
    # Manual Mode (Batch JSON Export)
    python main.py manual --input samples.txt --output ./exports

    # ML Mode (Graph Construction + Model Inference)
    python main.py ml --input report.json --model model.pt

Author: Antigravity Agent
License: MIT
"""

import argparse
import json
import sys
from pathlib import Path

# === Mode Handlers ===

def run_manual_mode(args):
    """
    MANUAL MODE: Process a list of Cuckoo JSON reports and export structured data.
    Input: Text file with paths to Cuckoo reports (one per line)
    Output: Directory with parsed JSON files ready for analysis
    """
    from cuckoo_parser import CuckooParser
    
    input_list = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not input_list.exists():
        print(f"[!] Input file not found: {input_list}")
        return 1
    
    # Read list of report paths
    with open(input_list, 'r') as f:
        report_paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"[*] Manual Mode: Processing {len(report_paths)} reports")
    print(f"[*] Output directory: {output_dir}")
    
    success = 0
    failed = 0
    
    for i, rpath in enumerate(report_paths):
        rpath = Path(rpath)
        if not rpath.exists():
            print(f"    [{i+1}] SKIP (not found): {rpath.name}")
            failed += 1
            continue
        
        try:
            parser = CuckooParser(rpath)
            data = parser.parse()
            
            # Export parsed data as JSON
            out_name = output_dir / f"{rpath.stem}_parsed.json"
            
            export_data = {
                "source": str(rpath),
                "processes": [
                    {"pid": p.pid, "ppid": p.ppid, "name": p.name}
                    for p in data.processes.values()
                ],
                "api_count": len(data.apis),
                "files": list(data.files),
                "network": list(data.network),
                "registry": list(data.registry),
                "api_sequence": [
                    {"name": a.name, "category": a.category, "pid": a.pid}
                    for a in data.apis[:100]  # Limit to first 100 for preview
                ]
            }
            
            with open(out_name, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"    [{i+1}] OK: {rpath.name} -> {out_name.name}")
            success += 1
            
        except Exception as e:
            print(f"    [{i+1}] FAIL: {rpath.name} - {e}")
            failed += 1
    
    print(f"\n[+] Complete: {success} success, {failed} failed")
    return 0 if failed == 0 else 1


def run_ml_mode(args):
    """
    ML MODE: Full pipeline with Graph Construction and Model Inference.
    Input: Single Cuckoo JSON report
    Output: Classification result (Malware/Benign)
    """
    try:
        import torch
        from cuckoo_parser import CuckooParser
        from build_hetero_graph import HeteroGraphBuilder
        from graph_pruning import NodeCentricPruner
        from models.h_graphsage import build_model_from_data
    except ImportError as e:
        print(f"[!] ML Mode requires PyTorch/PyG: {e}")
        print("[*] Install with: pip install torch torch_geometric networkx")
        return 1
    
    input_path = Path(args.input)
    model_path = Path(args.model) if args.model else None
    
    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        return 1
    
    print(f"[*] ML Mode: Processing {input_path.name}")
    
    # 1. Parse Cuckoo Report
    print("    [1/4] Parsing report...")
    parser = CuckooParser(input_path)
    report = parser.parse()
    
    # 2. Build Heterogeneous Graph
    print("    [2/4] Building graph...")
    builder = HeteroGraphBuilder()
    graph = builder.build(report)
    
    if graph is None:
        print("[!] Failed to build graph.")
        return 1
    
    # 3. Prune Graph (Optional)
    if not args.no_prune:
        print("    [3/4] Pruning graph...")
        pruner = NodeCentricPruner(nexus_ratio=0.2)
        graph = pruner.prune(graph)
    else:
        print("    [3/4] Skipping pruning...")
    
    # 4. Model Inference
    print("    [4/4] Running inference...")
    
    if model_path and model_path.exists():
        # Load trained model
        model = torch.load(model_path)
        model.eval()
    else:
        # Demo: Create model and run with random weights (untrained)
        print("        [!] No model provided, using untrained model for demo")
        model = build_model_from_data(graph)
        model.eval()
    
    with torch.no_grad():
        x_dict = {nt: graph[nt].x for nt in graph.node_types}
        edge_dict = {et: graph[et].edge_index for et in graph.edge_types}
        
        logits = model(x_dict, edge_dict)
        pred = logits.argmax(dim=-1).item()
        prob = torch.softmax(logits, dim=-1)[0]
    
    labels = ["Benign", "Malware"]
    result = labels[pred]
    confidence = prob[pred].item() * 100
    
    print(f"\n{'='*40}")
    print(f"  RESULT: {result}")
    print(f"  Confidence: {confidence:.1f}%")
    print(f"{'='*40}")
    
    # Save result
    if args.output:
        result_data = {
            "input": str(input_path),
            "prediction": result,
            "confidence": f"{confidence:.2f}%",
            "graph_stats": {
                "node_types": graph.node_types,
                "num_nodes": {nt: graph[nt].num_nodes for nt in graph.node_types}
            }
        }
        with open(args.output, 'w') as f:
            json.dump(result_data, f, indent=2)
        print(f"[+] Result saved to: {args.output}")
    
    return 0


# === CLI ===

def main():
    parser = argparse.ArgumentParser(
        description="HoloGuard - Malware Detection Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  manual    Batch process Cuckoo reports -> JSON (No ML)
  ml        Full pipeline with H-GraphSAGE inference

Examples:
  # Manual Mode
  python main.py manual --input samples.txt --output ./exports

  # ML Mode
  python main.py ml --input report.json --model trained.pt --output result.json
        """
    )
    
    subparsers = parser.add_subparsers(dest='mode', required=True)
    
    # Manual Mode
    manual_parser = subparsers.add_parser('manual', help='Batch JSON export (No ML)')
    manual_parser.add_argument('--input', '-i', required=True, help='Text file with list of Cuckoo report paths')
    manual_parser.add_argument('--output', '-o', default='./exports', help='Output directory')
    
    # ML Mode
    ml_parser = subparsers.add_parser('ml', help='Full ML pipeline')
    ml_parser.add_argument('--input', '-i', required=True, help='Single Cuckoo JSON report')
    ml_parser.add_argument('--model', '-m', default=None, help='Path to trained model (.pt)')
    ml_parser.add_argument('--output', '-o', default=None, help='Output result JSON')
    ml_parser.add_argument('--no-prune', action='store_true', help='Skip graph pruning')
    
    args = parser.parse_args()
    
    if args.mode == 'manual':
        return run_manual_mode(args)
    elif args.mode == 'ml':
        return run_ml_mode(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
