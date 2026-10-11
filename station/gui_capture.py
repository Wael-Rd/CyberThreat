import ctypes, os, subprocess, sys, time
from pathlib import Path
out=Path(sys.argv[1]); phase=sys.argv[2]
if phase not in ('vulnerable','hardened'): raise ValueError('Invalid phase')
env=dict(os.environ,DISPLAY=':99',XDG_CONFIG_HOME='/tmp/lab-gui-config',XDG_CACHE_HOME='/tmp/lab-gui-cache',XDG_RUNTIME_DIR='/tmp/lab-runtime',QT_XCB_GL_INTEGRATION='none')
Path(env['XDG_RUNTIME_DIR']).mkdir(exist_ok=True); Path(env['XDG_RUNTIME_DIR']).chmod(0o700)
x=subprocess.Popen(['Xvfb',':99','-screen','0','1280x900x24','-nolisten','tcp','-ac'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
w=None
try:
    time.sleep(1)
    filt='tcp.flags.syn == 1 && tcp.flags.ack == 0' if phase=='vulnerable' else 'http.response.code == 429'
    w=subprocess.Popen(['wireshark','-r',str(out/f'{phase}.pcap'),'-d','tcp.port==8080,http','-Y',filt],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    time.sleep(7)
    if w.poll() is not None: raise RuntimeError(w.stderr.read().decode())
    # Resize our own X11 window inside the container, without a host display.
    X=ctypes.CDLL('libX11.so.6'); D=ctypes.c_void_p; W=ctypes.c_ulong; U=ctypes.c_uint; I=ctypes.c_int
    X.XOpenDisplay.argtypes=[ctypes.c_char_p]; X.XOpenDisplay.restype=D
    X.XDefaultRootWindow.argtypes=[D]; X.XDefaultRootWindow.restype=W
    X.XQueryTree.argtypes=[D,W,ctypes.POINTER(W),ctypes.POINTER(W),ctypes.POINTER(ctypes.POINTER(W)),ctypes.POINTER(U)]
    X.XGetGeometry.argtypes=[D,W,ctypes.POINTER(W),ctypes.POINTER(I),ctypes.POINTER(I),ctypes.POINTER(U),ctypes.POINTER(U),ctypes.POINTER(U),ctypes.POINTER(U)]
    X.XMoveResizeWindow.argtypes=[D,W,I,I,U,U]; X.XFlush.argtypes=[D]
    display=X.XOpenDisplay(b':99'); root=X.XDefaultRootWindow(display)
    parent=W(); returned=W(); children=ctypes.POINTER(W)(); count=U()
    X.XQueryTree(display,root,ctypes.byref(returned),ctypes.byref(parent),ctypes.byref(children),ctypes.byref(count))
    for i in range(count.value):
        xx=I(); yy=I(); width=U(); height=U(); border=U(); depth=U()
        X.XGetGeometry(display,children[i],ctypes.byref(returned),ctypes.byref(xx),ctypes.byref(yy),ctypes.byref(width),ctypes.byref(height),ctypes.byref(border),ctypes.byref(depth))
        if width.value>500 and height.value>350: X.XMoveResizeWindow(display,children[i],0,0,1280,900)
    X.XFlush(display); time.sleep(1)
    subprocess.run(['xwd' ,'-display',':99','-root','-silent','-out',str(out/f'wireshark-{phase}.xwd')],check=True,timeout=10)
finally:
    if w is not None:
        w.terminate(); w.wait(timeout=10)
    x.terminate(); x.wait(timeout=10)
print('Wireshark GUI screenshot captured:',phase)
