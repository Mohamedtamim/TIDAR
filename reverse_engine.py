"""
Reverse Engineering Engine
Analyzes executables using Ghidra and extracts structured information
"""

import os
import subprocess
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib


class ReverseEngine:
    """Reverse engineering analysis engine using Ghidra"""
    
    def __init__(
        self,
        ghidra_binary: str = "/home/godfather/Desktop/ghidra_11.4.3_PUBLIC/support/analyzeHeadless",
        project_path: str = "/home/godfather/Desktop/GhidraProject",
        project_name: str = "AutoProject",
        scripts_path: str = "/home/godfather/Desktop/GhidraScripts",
        reports_dir: str = "/home/godfather/Desktop/GhidraReports"
    ):
        """
        Initialize reverse engineering engine
        
        Args:
            ghidra_binary: Path to Ghidra analyzeHeadless binary
            project_path: Path to Ghidra project directory
            project_name: Name of Ghidra project
            scripts_path: Path to Ghidra scripts directory
            reports_dir: Directory to save analysis reports
        """
        self.ghidra_binary = ghidra_binary
        self.project_path = Path(project_path)
        self.project_name = project_name
        self.scripts_path = Path(scripts_path)
        self.reports_dir = Path(reports_dir)
        
        # Ensure directories exist
        self.project_path.mkdir(parents=True, exist_ok=True)
        self.scripts_path.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Create JSON export script
        self._create_json_export_script()
    
    def _create_json_export_script(self):
        """Create Ghidra script to export analysis as JSON"""
        script_path = self.scripts_path / "export_analysis_json.py"
        
        script_content = '''# @category Reporting
# Export Ghidra analysis to JSON format
import json
import os
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SourceType

output_file = os.path.join(r'{reports_dir}', 'analysis_{timestamp}.json')

analysis_data = {{
    "sample_name": currentProgram.getName(),
    "sample_path": str(currentProgram.getExecutablePath()),
    "architecture": str(currentProgram.getLanguageID()),
    "functions": [],
    "strings": [],
    "imports": [],
    "sections": [],
    "errors": []
}}

try:
    # Extract Functions
    func_mgr = currentProgram.getFunctionManager()
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        analysis_data["functions"].append({{
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature())
        }})
except Exception as e:
    analysis_data["errors"].append("Error extracting functions: " + str(e))

try:
    # Extract Strings
    listing = currentProgram.getListing()
    strings = listing.getDefinedData(True)
    for s in strings:
        dt = s.getDataType()
        if dt.getName() == "string":
            try:
                value = str(s.getValue())
                if len(value) > 3:  # Filter out very short strings
                    analysis_data["strings"].append({{
                        "value": value,
                        "address": str(s.getMinAddress())
                    }})
            except:
                continue
except Exception as e:
    analysis_data["errors"].append("Error extracting strings: " + str(e))

try:
    # Extract Imports / External Functions
    ext_mgr = currentProgram.getExternalManager()
    ext_syms = ext_mgr.getExternalSymbols()
    for sym in ext_syms:
        if sym.getSource() == SourceType.IMPORTED:
            analysis_data["imports"].append({{
                "name": sym.getName(),
                "address": str(sym.getAddress())
            }})
except Exception as e:
    analysis_data["errors"].append("Error extracting imports: " + str(e))

try:
    # Extract Sections
    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()
    for block in blocks:
        analysis_data["sections"].append({{
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": str(block.getSize()),
            "permissions": str(block.getPermissions())
        }})
except Exception as e:
    analysis_data["errors"].append("Error extracting sections: " + str(e))

# Write JSON file
with open(output_file, 'w') as f:
    json.dump(analysis_data, f, indent=2)

print("[+] JSON analysis exported to: " + output_file)
print("JSON_OUTPUT_FILE:" + output_file)
'''.format(
            reports_dir=str(self.reports_dir),
            timestamp=time.strftime('%Y%m%d_%H%M%S')
        )
        
        with open(script_path, 'w') as f:
            f.write(script_content)
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze an executable file using Ghidra
        
        Args:
            file_path: Path to the executable file to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return {
                "error": f"File not found: {file_path}",
                "sample_name": file_path.name,
                "sample_path": str(file_path),
                "functions": [],
                "strings": [],
                "imports": [],
                "sections": [],
                "errors": [f"File not found: {file_path}"]
            }
        
        # Generate unique timestamp for this analysis
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_file = self.reports_dir / f'analysis_{timestamp}.json'
        
        # Update script with current timestamp
        self._create_json_export_script()
        
        # Calculate file hash
        file_hash = self._calculate_hash(file_path)
        
        # Get file metadata
        file_size = file_path.stat().st_size
        file_modified = time.ctime(file_path.stat().st_mtime)
        
        # Prepare Ghidra command
        cmd = [
            self.ghidra_binary,
            str(self.project_path),
            self.project_name,
            "-import", str(file_path),
            "-postScript", "export_analysis_json.py",
            "-scriptPath", str(self.scripts_path),
            "-overwrite",
            "-deleteProject"  # Clean up after analysis
        ]
        
        result = {
            "sample_name": file_path.name,
            "sample_path": str(file_path),
            "file_hash": file_hash,
            "file_size": file_size,
            "file_modified": file_modified,
            "architecture": "Unknown",
            "functions": [],
            "strings": [],
            "imports": [],
            "sections": [],
            "errors": [],
            "warnings": []
        }
        
        try:
            # Run Ghidra analysis
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Check if JSON file was created
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        ghidra_data = json.load(f)
                    
                    # Merge Ghidra results
                    result.update({
                        "architecture": ghidra_data.get("architecture", "Unknown"),
                        "functions": ghidra_data.get("functions", []),
                        "strings": ghidra_data.get("strings", []),
                        "imports": ghidra_data.get("imports", []),
                        "sections": ghidra_data.get("sections", []),
                        "errors": ghidra_data.get("errors", [])
                    })
                except json.JSONDecodeError as e:
                    result["errors"].append(f"Failed to parse Ghidra JSON output: {e}")
            else:
                # Try to find the most recent analysis file
                json_files = list(self.reports_dir.glob("analysis_*.json"))
                if json_files:
                    latest_file = max(json_files, key=lambda p: p.stat().st_mtime)
                    try:
                        with open(latest_file, 'r') as f:
                            ghidra_data = json.load(f)
                        result.update({
                            "architecture": ghidra_data.get("architecture", "Unknown"),
                            "functions": ghidra_data.get("functions", []),
                            "strings": ghidra_data.get("strings", []),
                            "imports": ghidra_data.get("imports", []),
                            "sections": ghidra_data.get("sections", []),
                            "errors": ghidra_data.get("errors", [])
                        })
                    except json.JSONDecodeError:
                        pass
            
            # Check for warnings in stderr
            if process.stderr:
                result["warnings"].append(f"Ghidra stderr: {process.stderr[:500]}")
            
            if process.returncode != 0:
                result["errors"].append(f"Ghidra analysis failed with return code {process.returncode}")
                
        except subprocess.TimeoutExpired:
            result["errors"].append("Ghidra analysis timed out (exceeded 5 minutes)")
        except FileNotFoundError:
            result["errors"].append(f"Ghidra binary not found at: {self.ghidra_binary}")
        except Exception as e:
            result["errors"].append(f"Error during analysis: {str(e)}")
        
        return result
    
    def _calculate_hash(self, file_path: Path) -> str:
        """Calculate MD5 hash of file"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            return "unknown"
    
    def analyze_from_json(self, json_file: str) -> List[Dict[str, Any]]:
        """
        Analyze files from a JSON log file (like Suspicious_Logs.json)
        
        Args:
            json_file: Path to JSON file containing file paths
            
        Returns:
            List of analysis results
        """
        results = []
        
        try:
            with open(json_file, 'r') as f:
                logs = json.load(f)
            
            for entry in logs:
                file_path = entry.get("file_path")
                if file_path and os.path.exists(file_path):
                    analysis = self.analyze_file(file_path)
                    # Add log metadata
                    analysis["log_metadata"] = {
                        "event_id": entry.get("event_id"),
                        "timestamp": entry.get("timestamp"),
                        "severity": entry.get("severity"),
                        "description": entry.get("description")
                    }
                    results.append(analysis)
                else:
                    results.append({
                        "error": f"File not found: {file_path}",
                        "log_metadata": entry
                    })
        except Exception as e:
            results.append({
                "error": f"Failed to process JSON file: {str(e)}"
            })
        
        return results


