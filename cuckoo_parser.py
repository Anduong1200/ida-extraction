#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Cuckoo Parser for HoloGuard
===========================
Parses Cuckoo Sandbox JSON reports to extract behavioral entities and relationships
for Heterogeneous Graph construction.

Supported Entities:
- Process (PID, Name, PPID)
- API (Name, Category, Arguments)
- File (Path)
- Network (IP, Domain)
- Registry (Key)

Author: Antigravity Agent
License: MIT
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ProcessNode:
    pid: int
    ppid: int
    name: str
    command_line: str = ""

@dataclass
class APINode:
    name: str
    category: str
    pid: int  # Process that called this API
    return_value: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

@dataclass
class FileNode:
    path: str

@dataclass
class NetworkNode:
    destination: str  # IP or Domain
    proto: str        # TCP/UDP/DNS

@dataclass
class RegistryNode:
    key: str
    value: str = ""

@dataclass
class ParsedReport:
    """Container for all extracted entities."""
    processes: Dict[int, ProcessNode] = field(default_factory=dict)
    apis: List[APINode] = field(default_factory=list)
    files: Set[str] = field(default_factory=set)
    network: Set[str] = field(default_factory=set)
    registry: Set[str] = field(default_factory=set)
    
    # Store relationships for easy graph building
    # Mapping: object_value -> list of APIs that interacted with it
    file_access: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list)) # file -> api_indices
    net_access: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list))  # net -> api_indices
    reg_access: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list))  # reg -> api_indices


from collections import defaultdict

class CuckooParser:
    """Parses Cuckoo JSON reports."""
    
    def __init__(self, report_path: Path):
        self.report_path = report_path
        self.data: ParsedReport = ParsedReport()
        self._raw_json: Dict = {}

    def parse(self) -> ParsedReport:
        """Main parsing logic."""
        logger.info(f"Parsing Cuckoo report: {self.report_path}")
        
        try:
            with open(self.report_path, 'r', encoding='utf-8') as f:
                self._raw_json = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load JSON: {e}")
            return self.data

        # 1. Extract Processes
        self._extract_processes()
        
        # 2. Extract API Calls (and implicit File/Net/Reg entities)
        self._extract_api_calls()
        
        # 3. Extract Explicit Network info (if available in 'network' section)
        self._extract_network_section()
        
        logger.info(f"Parsing complete. Found: {len(self.data.processes)} procs, {len(self.data.apis)} APIs")
        return self.data

    def _extract_processes(self):
        """Extract process hierarchy."""
        # Generic Cuckoo structure usually has 'behavior' -> 'processes'
        behavior = self._raw_json.get('behavior', {})
        processes = behavior.get('processes', [])
        
        # Also check 'generic' section of behavior if 'processes' is empty 
        # (different Cuckoo versions vary, sometimes it's 'apistats' or similar, 
        # but 'processes' is standard for full logs)
        
        for proc in processes:
            pid = proc.get('process_id')
            ppid = proc.get('parent_id')
            name = proc.get('process_name', 'unknown')
            cmd = proc.get('command_line', '')
            
            if pid is not None:
                self.data.processes[pid] = ProcessNode(pid, ppid, name, cmd)

    def _extract_api_calls(self):
        """Extract API calls and infer interactions."""
        # Cuckoo stores API calls inside each process object in 'behavior'
        behavior = self._raw_json.get('behavior', {})
        processes = behavior.get('processes', [])
        
        for proc in processes:
            pid = proc.get('process_id')
            calls = proc.get('calls', [])
            
            for call in calls:
                api_name = call.get('api')
                category = call.get('category')
                args = call.get('arguments', {})
                ret = call.get('return', '')
                time_val = call.get('time', 0.0)
                
                api_node = APINode(
                    name=api_name,
                    category=category,
                    pid=pid,
                    return_value=str(ret),
                    arguments=args,
                    timestamp=float(time_val)
                )
                
                # Add to list
                self.data.apis.append(api_node)
                api_idx = len(self.data.apis) - 1
                
                # Entity Extraction from Arguments
                self._infer_entities_from_args(api_idx, api_name, args)

    def _infer_entities_from_args(self, api_idx: int, api_name: str, args: Dict[str, Any]):
        """Heuristic to extract File/Reg/Net from API arguments."""
        # Normalize args keys (sometimes 'filepath', 'FileName', 'buffer', etc.)
        
        # Files
        if 'file' in api_name.lower() or 'path' in str(args).lower():
            for key, val in args.items():
                if isinstance(val, str) and ('\\' in val or '/' in val or 'C:' in val):
                     # Simple path detection heuristic
                    if len(val) > 3 and not val.startswith('HKEY'):
                        self.data.files.add(val)
                        self.data.file_access[val].append(api_idx)

        # Registry
        if 'reg' in api_name.lower() or 'key' in str(args).lower():
            for key, val in args.items():
                if isinstance(val, str) and (val.startswith('HKEY') or 'ControlSet' in val):
                    self.data.registry.add(val)
                    self.data.reg_access[val].append(api_idx)
                    
        # Network (Sockets, InternetConnect, etc.)
        if 'socket' in api_name.lower() or 'internet' in api_name.lower() or 'http' in api_name.lower():
            for key, val in args.items():
                # Heuristic IP or Domain check
                if isinstance(val, str) and ('.' in val or ':' in val):
                     # IP Regex or Domain Regex would be better, but simple check for now
                     if len(val) > 4 and val not in self.data.files:
                         self.data.network.add(val)
                         self.data.net_access[val].append(api_idx)

    def _extract_network_section(self):
        """Extract explicit network activity."""
        net = self._raw_json.get('network', {})
        
        # Hosts
        for host in net.get('hosts', []):
            if isinstance(host, dict): # Sometimes it's a list of strings
                 ip = host.get('ip')
                 if ip: self.data.network.add(ip)
            elif isinstance(host, str):
                 self.data.network.add(host)
                 
        # DNS
        for dns in net.get('dns', []):
            req = dns.get('request')
            if req: self.data.network.add(req)
            
        # TCP/UDP
        for p in net.get('tcp', []) + net.get('udp', []):
            dst = p.get('dst')
            if dst: self.data.network.add(dst)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Test Cuckoo Parser")
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    
    if args.report.exists():
        parser = CuckooParser(args.report)
        data = parser.parse()
        print(f"Processes: {len(data.processes)}")
        print(f"APIs: {len(data.apis)}")
        print(f"Files: {len(data.files)}")
        print(f"Registry: {len(data.registry)}")
        print(f"Network: {len(data.network)}")
    else:
        print("Report not found.")

if __name__ == "__main__":
    main()
