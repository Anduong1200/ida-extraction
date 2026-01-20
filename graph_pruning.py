#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
HoloGuard Graph Pruning (Node-Centric Pruning - NCP)
====================================================
Implements the graph reduction strategy defined in the HoloGuard research proposal.
Reduces graph size while preserving structural integrity and semantic meaning.

Algorithm:
1. Significance Score: Calculate Degree Centrality for all nodes.
2. Node Classification:
   - Nexus Nodes: Top k% highest degree nodes (Important APIs, Root Processes).
   - Connector Nodes: Nodes lying on shortest paths between Nexus Nodes (Max hops).
   - Sparse Nodes: Everything else.
3. Pruning: Remove Sparse Nodes and associated edges.

Usage:
    python graph_pruning.py input_graph.pt --output pruned_graph.pt --ratio 0.2

Author: Antigravity Agent
License: MIT
"""

import argparse
import torch
import copy
from pathlib import Path
from typing import Dict, List, Set, Tuple

try:
    from torch_geometric.data import HeteroData
    from torch_geometric.utils import to_networkx, degree
    import networkx as nx
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("[!] PyTorch/PyG/NetworkX not installed.")


class NodeCentricPruner:
    """
    Implements Node-Centric Pruning (NCP) for Heterogeneous Graphs.
    """
    
    def __init__(self, nexus_ratio: float = 0.15, max_connector_hops: int = 3):
        """
        Args:
            nexus_ratio: Top % of nodes to keep as "Nexus" (0.0 to 1.0)
            max_connector_hops: Max distance to search for connections between Nexus nodes.
        """
        self.nexus_ratio = nexus_ratio
        self.max_connector_hops = max_connector_hops
        
    def prune(self, data: 'HeteroData') -> 'HeteroData':
        """Main pruning method."""
        if not TORCH_AVAILABLE:
            return None
            
        print(f"[*] Starting NCP Pruning (Nexus Ratio: {self.nexus_ratio})")
        
        # 1. Convert to Homogeneous NetworkX for topological analysis
        #    (Simplifies centrality and pathfinding across node types)
        #    We maintain a mapping: nx_node_id -> (node_type, node_idx)
        G_nx, mapping_dict = self._to_homogeneous_networkx(data)
        
        if G_nx.number_of_nodes() == 0:
            print("[!] Graph is empty, skipping pruning.")
            return data

        # 2. Calculate Significance (Degree Centrality)
        #    Note: PageRank could be used here for better results.
        centrality = nx.degree_centrality(G_nx)
        
        # 3. Identify Nexus Nodes
        #    Sort nodes by centrality score
        sorted_nodes = sorted(centrality.items(), key=lambda x: x[1], reverse=True)
        num_nexus = max(1, int(len(sorted_nodes) * self.nexus_ratio))
        
        nexus_nodes = {node_id for node_id, score in sorted_nodes[:num_nexus]}
        print(f"    Identify Nexus: {len(nexus_nodes)} nodes (Top {self.nexus_ratio*100}%)")
        
        # 4. Identify Connector Nodes
        #    Find nodes on shortest paths between Nexus nodes (within max_hops).
        #    Optimization: Only check paths for Nexus nodes that are somewhat close?
        #    For now, we use a multi-source BFS or simple shortest_path approximation.
        #    To be efficient: We perform BFS from each Nexus node to find other Nexus nodes.
        
        connector_nodes = self._find_connectors(G_nx, nexus_nodes)
        print(f"    Identify Connectors: {len(connector_nodes)} nodes")
        
        # 5. Union of Keep Nodes
        keep_nodes_nx = nexus_nodes.union(connector_nodes)
        
        # 6. Reconstruct Subgraph (Hetero)
        pruned_data = self._subgraph_hetero(data, keep_nodes_nx, mapping_dict)
        
        # Stats
        orig_nodes = G_nx.number_of_nodes()
        new_nodes = sum(pruned_data[nt].num_nodes for nt in pruned_data.node_types)
        print(f"[+] Pruning Complete: {orig_nodes} -> {new_nodes} nodes (Reduced by {100*(1 - new_nodes/orig_nodes):.1f}%)")
        
        return pruned_data

    def _to_homogeneous_networkx(self, data: 'HeteroData') -> Tuple[nx.Graph, Dict]:
        """Convert HeteroData to NetworkX graph for analysis."""
        G = nx.Graph()
        mapping = {} # nx_id -> (type, idx)
        rev_mapping = {} # (type, idx) -> nx_id
        
        node_offset = 0
        
        # Add Nodes
        for node_type in data.node_types:
            num_nodes = data[node_type].num_nodes
            for i in range(num_nodes):
                nx_id = node_offset + i
                G.add_node(nx_id, type=node_type, original_idx=i)
                mapping[nx_id] = (node_type, i)
                rev_mapping[(node_type, i)] = nx_id
            node_offset += num_nodes
            
        # Add Edges
        for edge_type in data.edge_types:
            src_type, rel, dst_type = edge_type
            edge_index = data[edge_type].edge_index
            
            src_indices = edge_index[0].tolist()
            dst_indices = edge_index[1].tolist()
            
            for s, d in zip(src_indices, dst_indices):
                # Look up NX IDs
                # Careful: We need to know the offset for each type, but the rev_mapping handles it safely
                s_nx = rev_mapping.get((src_type, s))
                d_nx = rev_mapping.get((dst_type, d))
                
                if s_nx is not None and d_nx is not None:
                    G.add_edge(s_nx, d_nx)
                    
        return G, mapping

    def _find_connectors(self, G: nx.Graph, nexus_nodes: Set[int]) -> Set[int]:
        """Find Connector nodes lying on paths between Nexus nodes."""
        connectors = set()
        nexus_list = list(nexus_nodes)
        
        # Optimization: We cannot run all-pairs shortest path on large graphs.
        # Strategy: For each Nexus node, run BFS up to max_hops. 
        # If we hit another Nexus node, mark the path as Connectors.
        
        visited_paths = set() # Keep track of (u, v) pairs processed
        
        # To avoid N^2, we limit checking.
        # But `all_pairs_shortest_path` is too heavy.
        # Let's use `nx.shortest_path` only for nodes that are close?
        # A simpler heuristic for "Connector" in Malware Graphs:
        # Keep 1-hop neighbors of Nexus nodes that have degree > 1?
        # The Research Proposal specifically mentioned "Shortest Path".
        
        # Practical Implementation of "Connector Nodes":
        # Any node that is on a shortest path of length <= max_hops between ANY two nexus nodes.
        
        # We can implement this by:
        # 1. BFS from all Nexus nodes simultaneously (Multi-source BFS) to label distance to nearest Nexus.
        #    Actually, that just gives distance.
        
        # Let's restrict the search space.
        # Only check pairs if they share a component?
        
        # Compromise for performance:
        # Keep nodes that connect two Nexus nodes within `max_connector_hops`.
        # Iterate over all nodes v. If v is neighbor to >= 2 Nexus nodes, keep v. (2-hop connection)
        # If v is neighbor to a neighbor... (3-hop).
        
        # Better: BFS from Nexus Set.
        # Layer 0: Nexus
        # Layer 1: Neighbors of Nexus.
        # Layer 2: Neighbors of Layer 1.
        # If a node in Layer k connects back to a DIFFERENT Nexus node (visited from different source), it's a connector.
        
        # Let's use NetworkX `all_pairs_shortest_path` but restricted? No.
        
        # Let's stick to the Proposal's intent: "Preserve structure".
        # We will keep 1-hop neighbors of Nexus nodes as a baseline "Connector" set,
        # plus any node on a path between two "close" nexus nodes.
        
        # Heuristic 2:
        # Calculate Betweenness Centrality on a subgraph induced by (Nexus + 1-hop)? 
        # Too complex.
        
        # Implementation:
        # For every nexus node, find all simple paths of length <= max_hops to other nexus nodes.
        # Collect all nodes on these paths.
        
        # To speed up:
        # Create subgraph of only nodes within max_hops distance from ANY Nexus node.
        # Then check connectivity.
        
        for source in nexus_nodes:
            # BFS limited depth
            lengths = nx.single_source_shortest_path_length(G, source, cutoff=self.max_connector_hops)
            
            for target, dist in lengths.items():
                if target in nexus_nodes and target != source:
                    # Found a path to another Nexus node
                    # Reconstruct path? nx.shortest_path allows finding it.
                    # Only do this if we haven't processed pair
                    pair = tuple(sorted((source, target)))
                    if pair in visited_paths:
                        continue
                    visited_paths.add(pair)
                    
                    path = nx.shortest_path(G, source, target)
                    connectors.update(path)
                    
        return connectors

    def _subgraph_hetero(self, data: 'HeteroData', keep_nodes_nx: Set[int], mapping: Dict) -> 'HeteroData':
        """Reconstruct HeteroData keeping only selected nodes."""
        
        # 1. Group keep_nodes by type: {type: [indices]}
        keep_indices = defaultdict(list)
        for nx_id in keep_nodes_nx:
            ntype, idx = mapping[nx_id]
            keep_indices[ntype].append(idx)
            
        # 2. Sort and unique
        for ntype in keep_indices:
            keep_indices[ntype] = sorted(list(set(keep_indices[ntype])))
            
        # 3. Create mapping Old -> New Index for each type
        old_to_new = {}
        for ntype, indices in keep_indices.items():
            for new_idx, old_idx in enumerate(indices):
                old_to_new[(ntype, old_idx)] = new_idx
                
        # 4. Create new Data object
        new_data = HeteroData()
        
        # Copy Nodes (subset)
        for ntype in keep_indices:
            indices = torch.tensor(keep_indices[ntype], dtype=torch.long)
            # Copy features
            if hasattr(data[ntype], 'x') and data[ntype].x is not None:
                new_data[ntype].x = data[ntype].x[indices]
            
            new_data[ntype].num_nodes = len(keep_indices[ntype])
            
        # Copy Edges (if both endpoints kept)
        for edge_type in data.edge_types:
            src_type, rel, dst_type = edge_type
            
            # If either node type is completely pruned (empty), skip edge
            if src_type not in keep_indices or dst_type not in keep_indices:
                continue
                
            edge_index = data[edge_type].edge_index
            src = edge_index[0]
            dst = edge_index[1]
            
            # Mask
            # We need to check if src is in keep_indices[src_type] AND dst in keep_indices[dst_type]
            # Efficient way: 
            # 1. Create Lookup Tensor/Map? Or just iterate if small?
            # 2. Use torch.isin (newer torch) or simple map.
            
            # Since we have old_to_new dictionary:
            new_src = []
            new_dst = []
            
            for s, d in zip(src.tolist(), dst.tolist()):
                s_key = (src_type, s)
                d_key = (dst_type, d)
                
                if s_key in old_to_new and d_key in old_to_new:
                    new_src.append(old_to_new[s_key])
                    new_dst.append(old_to_new[d_key])
                    
            if new_src:
                new_data[edge_type].edge_index = torch.tensor([new_src, new_dst], dtype=torch.long)
            else:
                new_data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)
                
        return new_data


def main():
    parser = argparse.ArgumentParser(description="HoloGuard Graph Pruner")
    parser.add_argument('input', type=Path, help="Input .pt file")
    parser.add_argument('--output', type=Path, default=Path('pruned.pt'))
    parser.add_argument('--ratio', type=float, default=0.2, help="Nexus Ratio (0.0-1.0)")
    parser.add_argument('--hops', type=int, default=2, help="Max Connector Hops")
    
    args = parser.parse_args()
    
    if not TORCH_AVAILABLE:
        print("Error: Required libraries not installed.")
        return
        
    if args.input.exists():
        print(f"Loading {args.input}...")
        data = torch.load(args.input)
        
        pruner = NodeCentricPruner(nexus_ratio=args.ratio, max_connector_hops=args.hops)
        new_data = pruner.prune(data)
        
        torch.save(new_data, args.output)
        print(f"Saved pruned graph to {args.output}")
    else:
        print("Input file not found.")

if __name__ == "__main__":
    main()
