# -*- coding: utf-8 -*-
# generate_html_report.py
# سكريبت Ghidra لإنشاء تقرير HTML للملفات

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SourceType

report_file = "/home/godfather/Desktop/GhidraReports/report.html"

# فتح الملف
with open(report_file, "w") as f:
    f.write("<html><head><meta charset='UTF-8'><title>Ghidra Analysis Report</title></head><body>\n")
    f.write("<h1>Ghidra Analysis Report</h1>\n")

    # ===== Functions =====
    f.write("<h2>Functions</h2>\n")
    func_mgr = currentProgram.getFunctionManager()
    funcs = func_mgr.getFunctions(True)
    for func in funcs:
        f.write("<p>Function: {} at {}</p>\n".format(func.getName(), func.getEntryPoint()))

    # ===== Strings =====
    f.write("<h2>Strings</h2>\n")
    listing = currentProgram.getListing()
    strings = listing.getDefinedData(True)
    for s in strings:
        dt = s.getDataType()
        if dt.getName() == "string":
            try:
                f.write("<p>{} at {}</p>\n".format(s.getValue(), s.getMinAddress()))
            except:
                continue

    # ===== Imports / External Functions =====
    f.write("<h2>Imports / External Functions</h2>\n")
    ext_mgr = currentProgram.getExternalManager()
    ext_syms = ext_mgr.getExternalSymbols()
    for sym in ext_syms:
        if sym.getSource() == SourceType.IMPORTED:
            f.write("<p>{} at {}</p>\n".format(sym.getName(), sym.getAddress()))

    f.write("</body></html>\n")

print("[+] HTML report generated at:", report_file)
