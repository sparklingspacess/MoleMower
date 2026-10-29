import ctypes
import ctypes.wintypes as wt
import struct
import sys

pipeName = r'\\.\pipe\Mullvad VPN'
genericRead = 0x80000000
genericWrite = 0x40000000
openExisting = 3

k32 = ctypes.WinDLL('kernel32', use_last_error=True)

def OpenPipe():
    h = k32.CreateFileW(pipeName, genericRead | genericWrite, 0, None, openExisting, 0, None)
    err = ctypes.get_last_error()
    if h in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, -1):
        raise OSError(f"CreateFileW failed, you probably don't have Mullvad VPN running (or you don't have it installed)")
    return h

def PipeRead(h, size=65536):
    buf = ctypes.create_string_buffer(size)
    n = wt.DWORD(0)
    if not k32.ReadFile(h, buf, size, ctypes.byref(n), None):
        raise OSError(f"ReadFile failed, error code: {ctypes.get_last_error()}")
    return buf.raw[:n.value]

def PipeWrite(h, data: bytes):
    if not data:
        return
    n = wt.DWORD(0)
    if not k32.WriteFile(h, data, len(data), ctypes.byref(n), None):
        raise OSError(f"WriteFile failed, error code: {ctypes.get_last_error()}")

def RpcEncode(proto_msg) -> bytes:
    b = proto_msg.SerializeToString()
    return struct.pack('>BI', 0, len(b)) + b

def RpcDecode(data: bytes, cls):
    if len(data) < 5:
        return None
    length = struct.unpack('>I', data[1:5])[0]
    obj = cls()
    obj.ParseFromString(data[5:5 + length])
    return obj

try:
    import h2.connection, h2.config, h2.events
except ImportError:
    sys.exit("h2 isn't installed, run: py -m pip install h2")

svc = '/mullvad_daemon.management_interface.ManagementService/'

class PipeGrpc:
    def __init__(self, pipe_handle):
        self.h = pipe_handle
        cfg  = h2.config.H2Configuration(client_side=True, header_encoding='utf-8')
        self.h2 = h2.connection.H2Connection(config=cfg)
        self.h2.initiate_connection()
        self.Flush()
        self.DrainUntil(lambda evts: any(isinstance(e, h2.events.RemoteSettingsChanged) for e in evts))

    def Flush(self):
        d = self.h2.data_to_send(65536)
        if d:
            PipeWrite(self.h, d)

    def ReadEvents(self):
        raw = PipeRead(self.h)
        events = self.h2.receive_data(raw)
        self.Flush()
        return events

    def DrainUntil(self, predicate, maxRounds=10):
        for _ in range(maxRounds):
            evts = self.ReadEvents()
            if predicate(evts):
                return evts
        raise TimeoutError("Unexpectedly stalled")

    def Call(self, method: str, request, responseCls):
        sid = self.h2.get_next_available_stream_id()
        self.h2.send_headers(sid, [
            (':method',       'POST'),
            (':path',         svc + method),
            (':authority',    'mullvad-daemon'),
            (':scheme',       'http'),
            ('content-type',  'application/grpc+proto'),
            ('te',            'trailers'),
        ])
        self.h2.send_data(sid, RpcEncode(request), end_stream=True)
        self.Flush()

        responseBuf = b''
        trailers = {}

        while True:
            for ev in self.ReadEvents():
                if isinstance(ev, h2.events.DataReceived) and ev.stream_id == sid:
                    responseBuf += ev.data
                    self.h2.acknowledge_received_data(ev.flow_controlled_length, sid)
                    self.Flush()
                elif isinstance(ev, h2.events.TrailersReceived) and ev.stream_id == sid:
                    trailers = {
                        (k.decode() if isinstance(k, bytes) else k):
                        (v.decode() if isinstance(v, bytes) else v)
                        for k, v in ev.headers
                    }
                elif isinstance(ev, h2.events.StreamEnded) and ev.stream_id == sid:
                    status = int(trailers.get('grpc-status', '0'))
                    return RpcDecode(responseBuf, responseCls)

import management_interface_pb2 as pb
from google.protobuf import empty_pb2
from google.protobuf.wrappers_pb2 import StringValue, BoolValue

def main():

    try:
        h = OpenPipe()
    except OSError as e:
        sys.exit(f"Error when opening the pipe, error code: {e}")

    try:
        c = PipeGrpc(h)
    except Exception as e:
        k32.CloseHandle(h)

    from google.protobuf import empty_pb2

    empty = empty_pb2.Empty()

    print("Attempting to disconnect you...")
    c.Call('DisconnectTunnel', empty, empty_pb2.Empty)

    print("Grabbing your auth-token...")
    token = c.Call('GetWwwAuthToken', empty, StringValue)
    if c.Call('GetWwwAuthToken', empty, StringValue) is None:
        print("You seem to have no auth-token")
    else:
        print(token)

    print("Disconnected, logging you out...")
    c.Call('LogoutAccount', empty, empty_pb2.Empty)

    print("Logged out, have fun!")

    k32.CloseHandle(h)


if __name__ == '__main__':
    main()
