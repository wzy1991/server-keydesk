"""Verify the actual packaged EXE contains Windows icon resources (stdlib only)."""
import ctypes
from ctypes import wintypes
from pathlib import Path
import struct
import sys

binary=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'Server-Keydesk.exe'
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
kernel.LoadLibraryExW.argtypes=[wintypes.LPCWSTR,wintypes.HANDLE,wintypes.DWORD]
kernel.LoadLibraryExW.restype=wintypes.HMODULE
kernel.FindResourceW.argtypes=[wintypes.HMODULE,ctypes.c_void_p,ctypes.c_void_p]
kernel.FindResourceW.restype=wintypes.HRSRC
kernel.LoadResource.argtypes=[wintypes.HMODULE,wintypes.HRSRC]
kernel.LoadResource.restype=wintypes.HGLOBAL
kernel.LockResource.argtypes=[wintypes.HGLOBAL]
kernel.LockResource.restype=ctypes.c_void_p
kernel.SizeofResource.argtypes=[wintypes.HMODULE,wintypes.HRSRC]
kernel.SizeofResource.restype=wintypes.DWORD
kernel.FreeLibrary.argtypes=[wintypes.HMODULE]
module=kernel.LoadLibraryExW(str(binary.resolve()),None,0x22)
if not module:raise ctypes.WinError(ctypes.get_last_error())
def resource(kind,identifier):
    found=kernel.FindResourceW(module,identifier,kind)
    if not found:raise AssertionError(f'Missing EXE resource: type={kind}, id={identifier}')
    loaded=kernel.LoadResource(module,found)
    address=kernel.LockResource(loaded)
    if not address:raise ctypes.WinError(ctypes.get_last_error())
    return ctypes.string_at(address,kernel.SizeofResource(module,found))
try:
    group=resource(14,1)
    reserved,kind,count=struct.unpack_from('<HHH',group)
    assert reserved==0 and kind==1 and count>=7,'Missing multi-resolution icon group'
    dimensions=[]
    for i in range(count):
        width,height,_,_,planes,bits,size,identifier=struct.unpack_from('<BBBBHHIH',group,6+i*14)
        data=resource(3,identifier)
        assert len(data)==size and data.startswith(b'\x89PNG\r\n\x1a\n'),'Invalid icon image'
        actual=struct.unpack_from('>II',data,16)
        assert actual==(width or 256,height or 256) and planes==1 and bits==32,'Wrong icon dimensions/depth'
        dimensions.append(actual[0])
    assert set([16,24,32,48,64,128,256]).issubset(dimensions),'Missing taskbar/titlebar or Explorer size'
    assert b'PerMonitorV2' in resource(24,1),'Missing DPI-aware Windows manifest'
    print('PASS: EXE icon group 1; PNG sizes '+', '.join(map(str,dimensions))+'; DPI-aware manifest')
finally:kernel.FreeLibrary(module)
