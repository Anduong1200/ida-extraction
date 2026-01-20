#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
HoloGuard Heterogeneous Graph Builder
=====================================
Constructs PyTorch Geometric HeteroData objects from parsed Cuckoo reports.
Implements the Heterogeneous Schema:
  Process -[spawn]-> Process
  Process -[call]-> API
  API -[read/write]-> File
  API -[connect]-> Network
  API -[modify]-> Registry
  API -[next]-> API (Sequence)

Author: Antigravity Agent
License: MIT
"""

import argparse
from pathlib import Path
from collections import defaultdict
import hashlib
import torch
import numpy as np

try:
    from torch_geometric.data import HeteroData
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("[!] PyTorch Geometric not installed.")

from cuckoo_parser import CuckooParser, ParsedReport

class HeteroGraphBuilder:
    def __init__(self):
        self.node_maps = {
            'process': {},  # pid -> index
            'api': {},      # api_index (from parser) -> node_index
            'file': {},     # path -> index
            'network': {},  # ip/domain -> index
            'registry': {}  # key -> index
        }
        
    def build(self, report: ParsedReport) -> 'HeteroData':
        if not TORCH_AVAILABLE:
            return None
            
        data = HeteroData()
        
        # 1. Create Nodes & Index Mappings
        self._create_process_nodes(data, report)
        self._create_api_nodes(data, report)
        self._create_file_nodes(data, report)
        self._create_network_nodes(data, report)
        self._create_registry_nodes(data, report)
        
        # 2. Create Edges
        self._create_process_edges(data, report)
        self._create_api_edges(data, report) # links API to Process, File, Net, Reg
        self._create_sequence_edges(data, report) # API -> API (next)

        return data

    # --- Node Creation ---
    
    def _create_process_nodes(self, data, report):
        # Features: Dummy One-Hot or Hash of Name
        # For prototype: Just use 1-dim dummy
        pids = list(report.processes.keys())
        for idx, pid in enumerate(pids):
            self.node_maps['process'][pid] = idx
            
        # Dummy features (replace with Word2Vec of process name later)
        data['process'].x = torch.randn(len(pids), 16) 
        data['process'].num_nodes = len(pids)

    def _create_api_nodes(self, data, report):
        # Features: SAFE Embedding (Placeholder: Random)
        num_apis = len(report.apis)
        for i in range(num_apis):
            # Mapping is direct Identity since list is ordered
            self.node_maps['api'][i] = i
            
        data['api'].x = torch.randn(num_apis, 32) # API Embeddings
        data['api'].num_nodes = num_apis

    def _create_file_nodes(self, data, report):
        files = list(report.files)
        for idx, f in enumerate(files):
            self.node_maps['file'][f] = idx
            
        # Features: DistilBERT of path (Placeholder: Random)
        data['file'].x = torch.randn(len(files), 16)
        data['file'].num_nodes = len(files)

    def _create_network_nodes(self, data, report):
        nets = list(report.network)
        for idx, n in enumerate(nets):
            self.node_maps['network'][n] = idx
        
        data['network'].x = torch.randn(len(nets), 16)
        data['network'].num_nodes = len(nets)

    def _create_registry_nodes(self, data, report):
        regs = list(report.registry)
        for idx, r in enumerate(regs):
            self.node_maps['registry'][r] = idx
            
        data['registry'].x = torch.randn(len(regs), 16)
        data['registry'].num_nodes = len(regs)

    # --- Edge Creation ---

    def _create_process_edges(self, data, report):
        # Process -[spawn]-> Process
        src, dst = [], []
        for pid, proc in report.processes.items():
            ppid = proc.ppid
            if ppid in self.node_maps['process'] and pid in self.node_maps['process']:
                src.append(self.node_maps['process'][ppid])
                dst.append(self.node_maps['process'][pid])
        
        if src:
            data['process', 'spawn', 'process'].edge_index = torch.tensor([src, dst], dtype=torch.long)
        else:
            data['process', 'spawn', 'process'].edge_index = torch.empty((2, 0), dtype=torch.long)

    def _create_api_edges(self, data, report):
        # Process -[call]-> API
        p_src, a_dst = [], []
        
        # API -[access]-> File
        a_file_src, f_dst = [], []
        
        # API -[connect]-> Network
        a_net_src, n_dst = [], []
        
        # API -[modify]-> Registry
        a_reg_src, r_dst = [], []

        for i, api in enumerate(report.apis):
            # Process calls API
            if api.pid in self.node_maps['process']:
                p_src.append(self.node_maps['process'][api.pid])
                a_dst.append(i)
                
        # File Access (Inverted from parser maps)
        for f_path, api_indices in report.file_access.items():
            if f_path in self.node_maps['file']:
                f_idx = self.node_maps['file'][f_path]
                for a_idx in api_indices:
                    a_file_src.append(a_idx)
                    f_dst.append(f_idx)
                    
        # Net Access
        for n_val, api_indices in report.net_access.items():
            if n_val in self.node_maps['network']:
                n_idx = self.node_maps['network'][n_val]
                for a_idx in api_indices:
                    a_net_src.append(a_idx)
                    n_dst.append(n_idx)

        # Reg Access
        for r_key, api_indices in report.reg_access.items():
            if r_key in self.node_maps['registry']:
                r_idx = self.node_maps['registry'][r_key]
                for a_idx in api_indices:
                    a_reg_src.append(a_idx)
                    r_dst.append(r_idx)

        # Assign valid edges
        if p_src:
            data['process', 'call', 'api'].edge_index = torch.tensor([p_src, a_dst], dtype=torch.long)
        else:
             data['process', 'call', 'api'].edge_index = torch.empty((2, 0), dtype=torch.long)
             
        if a_file_src:
            data['api', 'access', 'file'].edge_index = torch.tensor([a_file_src, f_dst], dtype=torch.long)
        else:
             data['api', 'access', 'file'].edge_index = torch.empty((2, 0), dtype=torch.long)
             
        if a_net_src:
            data['api', 'connect', 'network'].edge_index = torch.tensor([a_net_src, n_dst], dtype=torch.long)
        else:
             data['api', 'connect', 'network'].edge_index = torch.empty((2, 0), dtype=torch.long)
            
        if a_reg_src:
            data['api', 'modify', 'registry'].edge_index = torch.tensor([a_reg_src, r_dst], dtype=torch.long)
        else:
             data['api', 'modify', 'registry'].edge_index = torch.empty((2, 0), dtype=torch.long)

    def _create_sequence_edges(self, data, report):
        # API -[next]-> API
        # Only link APIs from same Process
        
        # Group APIs by PID strictly ordered by timestamp (already in list order usually)
        pid_to_apis = defaultdict(list)
        for i, api in enumerate(report.apis):
            pid_to_apis[api.pid].append(i)
            
        src, dst = [], []
        for pid, indices in pid_to_apis.items():
            # Link i -> i+1
            for k in range(len(indices) - 1):
                src.append(indices[k])
                dst.append(indices[k+1])
                
        if src:
            data['api', 'next', 'api'].edge_index = torch.tensor([src, dst], dtype=torch.long)
        else:
             data['api', 'next', 'api'].edge_index = torch.empty((2, 0), dtype=torch.long)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('json_path', type=Path)
    parser.add_argument('--output', type=Path, default=Path('hetero_graph.pt'))
    args = parser.parse_args()
    
    if not TORCH_AVAILABLE:
        print("PyG not installed.")
        return

    # 1. Parse
    cparser = CuckooParser(args.json_path)
    report = cparser.parse()
    
    # 2. Build Graph
    builder = HeteroGraphBuilder()
    graph = builder.build(report)
    
    if graph:
        print("\n=== HeteroGraph Stats ===")
        print(graph)
        print(f"Metadata: {graph.metadata()}")
        
        torch.save(graph, args.output)
        print(f"\nSaved to {args.output}")

if __name__ == "__main__":
    main()
