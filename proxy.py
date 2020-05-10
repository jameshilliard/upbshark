import asyncio
import sys
from binascii import unhexlify

from const import PimCommand, UpbMessage, UpbTransmission, UPB_MESSAGE_TYPE, UPB_MESSAGE_PIMREPORT_TYPE, INITIAL_PIM_REG_QUERY_BASE
from util import cksum

class PIM(asyncio.Protocol):

    def __init__(self):
        self.server_transport = None
        self.buffer = b''

    def connection_made(self, transport):
        print("connected to PIM")
        self.connected = True
        self.transport = transport

    def line_received(self, line):
        command = UpbMessage(line[UPB_MESSAGE_TYPE])
        if command != UpbMessage.UPB_MESSAGE_IDLE:
            data = line[1:]
            print(f"PIM {command.name} data: {data}")
        if command == UpbMessage.UPB_MESSAGE_PIMREPORT:
            print(f"got pim report: {hex(line[UPB_MESSAGE_PIMREPORT_TYPE])} with len: {len(line)}")
            if len(line) > UPB_MESSAGE_PIMREPORT_TYPE:
                transmission = UpbTransmission(line[UPB_MESSAGE_PIMREPORT_TYPE])
                print(f"transmission: {transmission.name}")
                if transmission == UpbTransmission.UPB_PIM_REGISTERS:
                    register_data = unhexlify(line[UPB_MESSAGE_PIMREPORT_TYPE + 1:])
                    start = register_data[0]
                    register_val = register_data[1:]
                    print(f"start: {hex(start)} register_val: {register_val}")
                    if start == INITIAL_PIM_REG_QUERY_BASE:
                        print("got pim in initial phase query mode")

    def data_received(self, data):
        self.buffer += data
        while b'\r' in self.buffer:
            line, self.buffer = self.buffer.split(b'\r', 1)
            if len(line) > 1:
                self.line_received(line)
        if self.server_transport:
            self.server_transport.write(data)

    def connection_lost(self, *args):
        self.connected = False

class Upstart(asyncio.Protocol):

    def __init__(self, transport, protocol):
        self.client = protocol
        self.buffer = b''

    def connection_made(self, transport):
        print("Upstart connected")
        # save the transport
        self.transport = transport
        self.client.server_transport = self.transport

    def send_data(self, data):
        self.client.transport.write(data)

    def line_received(self, line):
        command = PimCommand(line[0])
        data = unhexlify(line[1:-2])
        crc = int(line[-2:], 16)
        computed_crc = cksum(data)
        if crc == computed_crc:
            print(f'Upstart {command.name} data: {data}')
        else:
            print(f'Upstart corrupt data line: {line}')

    def data_received(self, data):
        self.buffer += data
        while b'\r' in self.buffer:
            line, self.buffer = self.buffer.split(b'\r', 1)
            if len(line) > 1:
                self.line_received(line)
        self.send_data(data)

    def connection_lost(self, *args):
        self.client.server_transport = None

async def main():
    loop = asyncio.get_event_loop()

    client_t, client_p = await loop.create_connection(PIM, sys.argv[1], 2101)

    server = await loop.create_server(lambda: Upstart(client_t, client_p), '0.0.0.0', 2101)
    async with server:
        await server.serve_forever()

asyncio.run(main())
