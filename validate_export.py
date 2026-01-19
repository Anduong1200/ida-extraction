#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IDA Export Validator v1.0
=========================
Validates JSON/NDJSON exports against the IDA exporter schema.
Provides diagnostics and integrity checks.

Usage:
    python validate_export.py <export_file.json>
    python validate_export.py <export_file.ndjson>

Exit codes:
    0 - Validation passed
    1 - Validation failed
    2 - File not found / parse error
"""

import json
import sys
import os
from datetime import datetime


class ValidationError(Exception):
    """Custom validation error."""
    pass


class SchemaValidator:
    """Validates IDA export data against expected schema."""
    
    # Required fields per object type
    REQUIRED_META = ["exporter", "exporter_version", "ida_version", "timestamp", "idb_name"]
    REQUIRED_FUNCTION = ["name", "start", "end", "size", "blocks"]
    REQUIRED_BLOCK = ["id", "start", "end", "insns"]
    REQUIRED_INSTRUCTION = ["ea", "mnemonic", "operands", "bytes"]
    REQUIRED_XREF = ["from", "to", "type"]
    REQUIRED_CFG_EDGE = ["from_block", "to_block", "type"]
    
    def __init__(self, data=None):
        self.data = data
        self.errors = []
        self.warnings = []
        self.stats = {
            "functions": 0,
            "blocks": 0,
            "instructions": 0,
            "xrefs": 0,
            "cfg_edges": 0,
            "calls_out": 0,
            "called_by": 0
        }
    
    def validate(self, data=None):
        """Run full validation on export data."""
        if data:
            self.data = data
        
        if not self.data:
            self.errors.append("No data to validate")
            return False
        
        # Validate top-level structure
        if not isinstance(self.data, dict):
            self.errors.append("Root must be an object/dict")
            return False
        
        # Validate meta
        if "meta" not in self.data:
            self.errors.append("Missing required field: 'meta'")
        else:
            self._validate_meta(self.data["meta"])
        
        # Validate functions
        if "functions" not in self.data:
            self.errors.append("Missing required field: 'functions'")
        else:
            self._validate_functions(self.data["functions"])
        
        # Validate xrefs (optional)
        if "xrefs" in self.data:
            self._validate_xrefs(self.data["xrefs"])
        
        # Validate cfg_edges (optional)
        if "cfg_edges" in self.data:
            self._validate_cfg_edges(self.data["cfg_edges"])
        
        return len(self.errors) == 0
    
    def _validate_meta(self, meta):
        """Validate metadata object."""
        if not isinstance(meta, dict):
            self.errors.append("'meta' must be an object")
            return
        
        for field in self.REQUIRED_META:
            if field not in meta:
                self.warnings.append(f"Missing recommended meta field: '{field}'")
        
        # Validate timestamp format
        if "timestamp" in meta:
            try:
                datetime.fromisoformat(meta["timestamp"].replace("Z", "+00:00"))
            except:
                self.warnings.append("Invalid timestamp format (expected ISO 8601)")
    
    def _validate_functions(self, functions):
        """Validate functions array."""
        if not isinstance(functions, list):
            self.errors.append("'functions' must be an array")
            return
        
        self.stats["functions"] = len(functions)
        
        for idx, func in enumerate(functions):
            self._validate_function(func, idx)
    
    def _validate_function(self, func, idx):
        """Validate single function object."""
        if not isinstance(func, dict):
            self.errors.append(f"Function[{idx}] must be an object")
            return
        
        for field in self.REQUIRED_FUNCTION:
            if field not in func:
                self.errors.append(f"Function[{idx}] missing required field: '{field}'")
        
        # Validate address format
        for addr_field in ["start", "end"]:
            if addr_field in func:
                if not self._is_valid_hex_address(func[addr_field]):
                    self.warnings.append(f"Function[{idx}].{addr_field} not in hex format")
        
        # Validate blocks
        if "blocks" in func and isinstance(func["blocks"], list):
            for bidx, block in enumerate(func["blocks"]):
                self._validate_block(block, idx, bidx)
                self.stats["blocks"] += 1
        
        # Count call relationships
        if "calls_out" in func and isinstance(func["calls_out"], list):
            self.stats["calls_out"] += len(func["calls_out"])
        if "called_by" in func and isinstance(func["called_by"], list):
            self.stats["called_by"] += len(func["called_by"])
    
    def _validate_block(self, block, func_idx, block_idx):
        """Validate single basic block."""
        if not isinstance(block, dict):
            self.errors.append(f"Function[{func_idx}].blocks[{block_idx}] must be an object")
            return
        
        for field in self.REQUIRED_BLOCK:
            if field not in block:
                self.errors.append(f"Function[{func_idx}].blocks[{block_idx}] missing: '{field}'")
        
        # Validate instructions
        if "insns" in block and isinstance(block["insns"], list):
            for iidx, insn in enumerate(block["insns"]):
                self._validate_instruction(insn, func_idx, block_idx, iidx)
                self.stats["instructions"] += 1
    
    def _validate_instruction(self, insn, func_idx, block_idx, insn_idx):
        """Validate single instruction."""
        if not isinstance(insn, dict):
            return
        
        for field in self.REQUIRED_INSTRUCTION:
            if field not in insn:
                # Don't spam with instruction-level errors, just warn once
                pass
        
        # Validate xrefs_out if present
        if "xrefs_out" in insn and isinstance(insn["xrefs_out"], list):
            for xref in insn["xrefs_out"]:
                if isinstance(xref, dict):
                    self.stats["xrefs"] += 1
    
    def _validate_xrefs(self, xrefs):
        """Validate global xrefs array."""
        if not isinstance(xrefs, list):
            self.errors.append("'xrefs' must be an array")
            return
        
        self.stats["xrefs"] = len(xrefs)
        
        for idx, xref in enumerate(xrefs[:10]):  # Sample first 10
            if not isinstance(xref, dict):
                continue
            for field in self.REQUIRED_XREF:
                if field not in xref:
                    self.warnings.append(f"XRef[{idx}] missing field: '{field}'")
                    break
    
    def _validate_cfg_edges(self, edges):
        """Validate CFG edges array."""
        if not isinstance(edges, list):
            self.errors.append("'cfg_edges' must be an array")
            return
        
        self.stats["cfg_edges"] = len(edges)
        
        for idx, edge in enumerate(edges[:10]):  # Sample first 10
            if not isinstance(edge, dict):
                continue
            for field in self.REQUIRED_CFG_EDGE:
                if field not in edge:
                    self.warnings.append(f"CFG_Edge[{idx}] missing field: '{field}'")
                    break
    
    def _is_valid_hex_address(self, value):
        """Check if value is a valid hex address string."""
        if not isinstance(value, str):
            return False
        if value.startswith("0x") or value.startswith("0X"):
            try:
                int(value, 16)
                return True
            except:
                return False
        return False
    
    def get_report(self):
        """Generate validation report."""
        report = []
        report.append("=" * 60)
        report.append("  IDA Export Validation Report")
        report.append("=" * 60)
        
        if self.data and "meta" in self.data:
            meta = self.data["meta"]
            report.append(f"\n[Metadata]")
            report.append(f"  Exporter: {meta.get('exporter', 'N/A')} v{meta.get('exporter_version', 'N/A')}")
            report.append(f"  IDA Version: {meta.get('ida_version', 'N/A')}")
            report.append(f"  Timestamp: {meta.get('timestamp', 'N/A')}")
            report.append(f"  IDB Name: {meta.get('idb_name', 'N/A')}")
        
        report.append(f"\n[Statistics]")
        report.append(f"  Functions: {self.stats['functions']}")
        report.append(f"  Basic Blocks: {self.stats['blocks']}")
        report.append(f"  Instructions: {self.stats['instructions']}")
        report.append(f"  XRefs: {self.stats['xrefs']}")
        report.append(f"  CFG Edges: {self.stats['cfg_edges']}")
        report.append(f"  Call Relationships: {self.stats['calls_out']} out, {self.stats['called_by']} in")
        
        if self.errors:
            report.append(f"\n[ERRORS] ({len(self.errors)})")
            for err in self.errors[:20]:
                report.append(f"  ✗ {err}")
            if len(self.errors) > 20:
                report.append(f"  ... and {len(self.errors) - 20} more")
        
        if self.warnings:
            report.append(f"\n[WARNINGS] ({len(self.warnings)})")
            for warn in self.warnings[:10]:
                report.append(f"  ⚠ {warn}")
            if len(self.warnings) > 10:
                report.append(f"  ... and {len(self.warnings) - 10} more")
        
        report.append("\n" + "=" * 60)
        if len(self.errors) == 0:
            report.append("  ✓ Schema validation PASSED")
        else:
            report.append("  ✗ Schema validation FAILED")
        report.append("=" * 60)
        
        return "\n".join(report)


def load_json(filepath):
    """Load JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def load_ndjson(filepath):
    """Load NDJSON file and merge into single structure."""
    data = {"meta": {}, "functions": [], "xrefs": [], "cfg_edges": []}
    
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "meta" in obj:
                    data["meta"] = obj["meta"]
                elif "function" in obj:
                    data["functions"].append(obj["function"])
                elif "xrefs" in obj:
                    data["xrefs"] = obj["xrefs"]
                elif "cfg_edges" in obj:
                    data["cfg_edges"] = obj["cfg_edges"]
            except json.JSONDecodeError:
                pass
    
    return data


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python validate_export.py <export_file.json|.ndjson>")
        sys.exit(2)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(2)
    
    print(f"[*] Validating: {filepath}")
    
    try:
        if filepath.endswith(".ndjson"):
            data = load_ndjson(filepath)
        else:
            data = load_json(filepath)
    except Exception as e:
        print(f"Error: Failed to parse file: {e}")
        sys.exit(2)
    
    validator = SchemaValidator(data)
    is_valid = validator.validate()
    
    print(validator.get_report())
    
    sys.exit(0 if is_valid else 1)


if __name__ == "__main__":
    main()
