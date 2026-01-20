#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
HoloGuard Heterogeneous GraphSAGE (H-GraphSAGE)
===============================================
Implements heterogeneous graph neural network for malware detection.
Uses edge-type specific aggregators and inductive learning.

Architecture:
- HeteroConv layers with SAGEConv per edge type
- Global pooling to get graph-level embedding
- MLP classifier for Malware/Benign

Usage:
    from models.h_graphsage import HGraphSAGE
    model = HGraphSAGE(metadata)
    out = model(hetero_data.x_dict, hetero_data.edge_index_dict)

Author: Antigravity Agent
License: MIT
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

try:
    from torch_geometric.nn import SAGEConv, HeteroConv, Linear, global_mean_pool
    from torch_geometric.data import HeteroData
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    print("[!] PyTorch Geometric not installed.")


class HGraphSAGE(nn.Module):
    """
    Heterogeneous GraphSAGE for Malware Detection.
    
    Args:
        metadata: Tuple (node_types, edge_types) from HeteroData.metadata()
        hidden_channels: Hidden layer dimension
        out_channels: Number of output classes (2 for binary classification)
        num_layers: Number of GNN layers
    """
    
    def __init__(
        self,
        metadata,
        in_channels_dict: dict,
        hidden_channels: int = 64,
        out_channels: int = 2,
        num_layers: int = 2,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.node_types = metadata[0]
        self.edge_types = metadata[1]
        self.hidden_channels = hidden_channels
        self.num_layers = num_layers
        self.dropout = dropout
        
        # Input Projection: Project each node type to hidden_channels
        self.lin_dict = nn.ModuleDict()
        for node_type in self.node_types:
            in_dim = in_channels_dict.get(node_type, 16)  # Default if missing
            self.lin_dict[node_type] = Linear(in_dim, hidden_channels)
        
        # Hetero Convolutions
        self.convs = nn.ModuleList()
        for _ in range(num_layers):
            # Create a SAGEConv for each edge type
            conv_dict = {}
            for edge_type in self.edge_types:
                conv_dict[edge_type] = SAGEConv(
                    (hidden_channels, hidden_channels),
                    hidden_channels,
                    aggr='mean'  # 'mean', 'max', 'sum' are options
                )
            self.convs.append(HeteroConv(conv_dict, aggr='sum'))
        
        # Graph-level Readout and Classifier
        # We will pool over all node types
        self.classifier = nn.Sequential(
            nn.Linear(hidden_channels * len(self.node_types), hidden_channels),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_channels, out_channels)
        )

    def forward(self, x_dict, edge_index_dict, batch_dict=None):
        """
        Forward pass.
        
        Args:
            x_dict: Dict[node_type, Tensor] of node features
            edge_index_dict: Dict[edge_type, Tensor] of edge indices
            batch_dict: Optional Dict[node_type, Tensor] for batching graphs
            
        Returns:
            Logits (batch_size, num_classes) if batch_dict provided,
            else (1, num_classes) for single graph.
        """
        # 1. Project all node types to hidden dimension
        h_dict = {}
        for node_type in self.node_types:
            if node_type in x_dict and x_dict[node_type] is not None:
                h_dict[node_type] = self.lin_dict[node_type](x_dict[node_type])
                h_dict[node_type] = F.relu(h_dict[node_type])
            else:
                # Handle missing node types (e.g., empty graph subset)
                # Create a dummy zero tensor
                h_dict[node_type] = torch.zeros((0, self.hidden_channels), device=next(self.parameters()).device)
        
        # 2. Message Passing Layers
        for conv in self.convs:
            h_dict = conv(h_dict, edge_index_dict)
            # Apply ReLU and Dropout
            h_dict = {key: F.dropout(F.relu(h), p=self.dropout, training=self.training) 
                      for key, h in h_dict.items()}
        
        # 3. Readout: Pool each node type, then concatenate
        pooled = []
        for node_type in self.node_types:
            h = h_dict.get(node_type)
            if h is not None and h.size(0) > 0:
                if batch_dict is not None and node_type in batch_dict:
                    # Batched graphs: use global_mean_pool
                    p = global_mean_pool(h, batch_dict[node_type])
                else:
                    # Single graph: mean over all nodes of this type
                    p = h.mean(dim=0, keepdim=True)
            else:
                # No nodes of this type; use zero placeholder
                batch_size = 1
                if batch_dict is not None:
                    # Determine batch size from another node type
                    for nt, b in batch_dict.items():
                        if b is not None and b.numel() > 0:
                            batch_size = b.max().item() + 1
                            break
                p = torch.zeros((batch_size, self.hidden_channels), device=next(self.parameters()).device)
            pooled.append(p)
        
        # Concatenate pooled embeddings from all node types
        graph_emb = torch.cat(pooled, dim=-1)  # (batch_size, hidden * num_node_types)
        
        # 4. Classification
        out = self.classifier(graph_emb)
        
        return out
    
    def get_embedding(self, x_dict, edge_index_dict, batch_dict=None):
        """Get graph-level embedding without classification head."""
        # Reuse forward logic up to pooling
        h_dict = {}
        for node_type in self.node_types:
            if node_type in x_dict and x_dict[node_type] is not None:
                h_dict[node_type] = self.lin_dict[node_type](x_dict[node_type])
                h_dict[node_type] = F.relu(h_dict[node_type])
            else:
                h_dict[node_type] = torch.zeros((0, self.hidden_channels), device=next(self.parameters()).device)
        
        for conv in self.convs:
            h_dict = conv(h_dict, edge_index_dict)
            h_dict = {key: F.relu(h) for key, h in h_dict.items()}
        
        pooled = []
        for node_type in self.node_types:
            h = h_dict.get(node_type)
            if h is not None and h.size(0) > 0:
                if batch_dict is not None and node_type in batch_dict:
                    p = global_mean_pool(h, batch_dict[node_type])
                else:
                    p = h.mean(dim=0, keepdim=True)
            else:
                batch_size = 1
                p = torch.zeros((batch_size, self.hidden_channels), device=next(self.parameters()).device)
            pooled.append(p)
        
        return torch.cat(pooled, dim=-1)


def build_model_from_data(data: 'HeteroData', hidden: int = 64, classes: int = 2) -> HGraphSAGE:
    """Helper to create model from HeteroData."""
    metadata = data.metadata()
    
    # Extract input channels per node type
    in_channels = {}
    for nt in metadata[0]:
        if hasattr(data[nt], 'x') and data[nt].x is not None:
            in_channels[nt] = data[nt].x.size(-1)
        else:
            in_channels[nt] = 16  # Default
            
    model = HGraphSAGE(
        metadata=metadata,
        in_channels_dict=in_channels,
        hidden_channels=hidden,
        out_channels=classes
    )
    
    return model


# === Training Loop Example ===
def train_example():
    """Example training loop (for reference)."""
    if not TORCH_AVAILABLE:
        print("PyG not available.")
        return
        
    from torch_geometric.loader import DataLoader
    
    # Assume we have a list of HeteroData graphs with labels (data.y)
    # graphs = [data1, data2, ...]
    # loader = DataLoader(graphs, batch_size=32, shuffle=True)
    
    # model = build_model_from_data(graphs[0])
    # optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    # criterion = nn.CrossEntropyLoss()
    
    # for epoch in range(100):
    #     model.train()
    #     total_loss = 0
    #     for batch in loader:
    #         optimizer.zero_grad()
    #         out = model(batch.x_dict, batch.edge_index_dict, batch.batch_dict)
    #         loss = criterion(out, batch.y)
    #         loss.backward()
    #         optimizer.step()
    #         total_loss += loss.item()
    #     print(f"Epoch {epoch}: Loss = {total_loss/len(loader):.4f}")
    
    print("See code comments for training loop structure.")


if __name__ == "__main__":
    train_example()
