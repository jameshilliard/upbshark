import asyncio
import sys

class PIM(asyncio.Protocol):

    def __init__(self):
        self.server_transport = None
        self.buffer = b''

    def connection_made(self, transport):
        print("connected to PIM")
        self.connected = True
        self.transport = transport

    def line_received(self, line):
        print(f"PIM line: {line}")

    def data_received(self, data):
        self.buffer += data
        while b'\r' in self.buffer:
            line, self.buffer = self.buffer.split(b'\r', 1)
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
        print(f"Upstart line: {line}")

    def data_received(self, data):
        self.buffer += data
        while b'\r' in self.buffer:
            line, self.buffer = self.buffer.split(b'\r', 1)
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
