"""Inspect a running Keydesk process tree without controlling its UI."""
import ctypes
from ctypes import wintypes

class ProcessEntry(ctypes.Structure):
    _fields_=[('size',wintypes.DWORD),('usage',wintypes.DWORD),('pid',wintypes.DWORD),('heap',ctypes.c_size_t),('module',wintypes.DWORD),('threads',wintypes.DWORD),('parent',wintypes.DWORD),('priority',wintypes.LONG),('flags',wintypes.DWORD),('name',wintypes.WCHAR*260)]
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
kernel.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD]
kernel.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
kernel.Process32FirstW.argtypes=[wintypes.HANDLE,ctypes.POINTER(ProcessEntry)]
kernel.Process32NextW.argtypes=[wintypes.HANDLE,ctypes.POINTER(ProcessEntry)]
kernel.CloseHandle.argtypes=[wintypes.HANDLE]
snapshot=kernel.CreateToolhelp32Snapshot(2,0)
if snapshot==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
try:
    item=ProcessEntry();item.size=ctypes.sizeof(item);processes={}
    ok=kernel.Process32FirstW(snapshot,ctypes.byref(item))
    while ok:
        processes[item.pid]=(item.parent,item.name)
        ok=kernel.Process32NextW(snapshot,ctypes.byref(item))
finally:kernel.CloseHandle(snapshot)
roots={pid for pid,(_,name) in processes.items() if name.lower()=='server-keydesk.exe'}
assert roots,'Start the native Keydesk release before running this check'
descendants=set(roots)
while True:
    more={pid for pid,(parent,_) in processes.items() if parent in descendants}
    updated=descendants|more
    if updated==descendants:break
    descendants=updated
children=[processes[pid][1] for pid in descendants-roots]
assert not any('webview' in name.lower() or name.lower() in ('chrome.exe','msedge.exe') for name in children),'Browser process present under Keydesk: '+str(children)
print(f'PASS: {len(roots)} running Keydesk process(es); no WebView/browser descendants. Children: {children}')
