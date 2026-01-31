# @category Reporting
# Export Ghidra analysis to JSON format
import json
import os
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SourceType

output_file = os.path.join(r'/home/godfather/Desktop/GhidraReports', 'analysis_20251210_160856.json')

analysis_data = {
    "sample_name": currentProgram.getName(),
    "sample_path": str(currentProgram.getExecutablePath()),
    "architecture": str(currentProgram.getLanguageID()),
    "functions": [],
    "strings": [],
    "imports": [],
    "sections": [],
    "errors": []
}

try:
    # Extract Functions
    func_mgr = currentProgram.getFunctionManager()
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        analysis_data["functions"].append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature())
        })
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
                    analysis_data["strings"].append({
                        "value": value,
                        "address": str(s.getMinAddress())
                    })
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
            analysis_data["imports"].append({
                "name": sym.getName(),
                "address": str(sym.getAddress())
            })
except Exception as e:
    analysis_data["errors"].append("Error extracting imports: " + str(e))

try:
    # Extract Sections
    memory = currentProgram.getMemory()
    blocks = memory.getBlocks()
    for block in blocks:
        analysis_data["sections"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": str(block.getSize()),
            "permissions": str(block.getPermissions())
        })
except Exception as e:
    analysis_data["errors"].append("Error extracting sections: " + str(e))

# Write JSON file
with open(output_file, 'w') as f:
    json.dump(analysis_data, f, indent=2)

print("[+] JSON analysis exported to: " + output_file)
print("JSON_OUTPUT_FILE:" + output_file)
