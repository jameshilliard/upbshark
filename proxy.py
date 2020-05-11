import asyncio
import sys
from pprint import pprint
from binascii import unhexlify

from const import PimCommand, UpbMessage, UpbDeviceId, UpbTransmission, UpbReqAck, UpbReqRepeater, \
MdidSet, MdidCoreCmd, MdidDeviceControlCmd, MdidCoreReport, \
UPB_MESSAGE_TYPE, UPB_MESSAGE_PIMREPORT_TYPE, INITIAL_PIM_REG_QUERY_BASE, PACKETHEADER_LINKBIT
from util import cksum

class PIM(asyncio.Protocol):

    def __init__(self):
        self.server_transport = None
        self.buffer = b''
        self.last_command = b''

    def connection_made(self, transport):
        print("connected to PIM")
        self.connected = True
        self.transport = transport

    def get_response_type(self):
        cmd = self.last_command[1]
        print(f"cmd: {hex(cmd)}")
        return (((cmd) >> 8) & 0xe0)

    def line_received(self, line):
        if UpbMessage.has_value(line[UPB_MESSAGE_TYPE]):
            command = UpbMessage(line[UPB_MESSAGE_TYPE])
            if command != UpbMessage.UPB_MESSAGE_IDLE:
                data = line[1:]
                print(f"PIM {command.name} data: {data}")
            if command == UpbMessage.UPB_MESSAGE_PIMREPORT:
                print(f"got pim report: {hex(line[UPB_MESSAGE_PIMREPORT_TYPE])} with len: {len(line)}")
                if len(line) > UPB_MESSAGE_PIMREPORT_TYPE:
                    response_type = self.get_response_type()
                    print(f"response_type: {hex(response_type)}")
                    #message_type = 
                    transmission = UpbTransmission(line[UPB_MESSAGE_PIMREPORT_TYPE])
                    print(f"transmission: {transmission.name}")
                    if transmission == UpbTransmission.UPB_PIM_REGISTERS:
                        register_data = unhexlify(line[UPB_MESSAGE_PIMREPORT_TYPE + 1:])
                        start = register_data[0]
                        register_val = register_data[1:]
                        print(f"start: {hex(start)} register_val: {register_val}")
                        if start == INITIAL_PIM_REG_QUERY_BASE:
                            print("got pim in initial phase query mode")
                    elif transmission == UpbTransmission.UPB_PIM_ACCEPT:
                        print("got pim accept")
                else:
                    print(f'got corrupt pim report: {hex(line[UPB_MESSAGE_PIMREPORT_TYPE])} with len: {len(line)}')
        else:
            print(f'PIM failed to parse line: {line}')

        #elif command == UpbMessage.UPB_MESSAGE_PIMREPORT:

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
        self.client.last_command = data
        crc = int(line[-2:], 16)
        computed_crc = cksum(data)
        if crc == computed_crc:
            print(f'Upstart {command.name} data: {data}')
            if command == PimCommand.UPB_NETWORK_TRANSMIT:
                control_word = data[0:2]
                link_bit = control_word[0] & PACKETHEADER_LINKBIT >> 7
                repeater_request = UpbReqRepeater(control_word[0] & 0x60 >> 5)
                data_len = control_word[0] & 0x1f
                assert(data_len == len(data) + 1)
                reserved = control_word[1] & 0x80 >> 7
                assert(reserved == 0x00)
                ack_request = UpbReqAck(control_word[1] & 0x70 >> 4)
                transmit_cnt = control_word[1] & 0x0c >> 2
                transmit_seq = control_word[1] & 0x03
                network_id = data[2]
                destination_id = data[3]
                device_id = UpbDeviceId(data[4])
                mdid_set = MdidSet(data[5] & 0xe0)
                if mdid_set == MdidSet.MDID_CORE_COMMANDS:
                    mdid_cmd = MdidCoreCmd(data[5] & 0x1f)
                elif mdid_set == MdidSet.MDID_DEVICE_CONTROL_COMMANDS:
                    mdid_cmd = MdidDeviceControlCmd(data[5] & 0x1f)
                elif mdid_set == MdidSet.MDID_CORE_REPORTS:
                    mdid_cmd = MdidCoreReport(data[5] & 0x1f)
                last_command = {
                    'link_bit': link_bit,
                    'repeater_request': repeater_request,
                    'ack_request': ack_request,
                    'transmit_cnt': transmit_cnt,
                    'transmit_seq': transmit_seq,
                    'network_id': network_id,
                    'destination_id': destination_id,
                    'device_id': device_id,
                    'mdid_set': mdid_set,
                    'mdid_cmd': mdid_cmd,
                    'data_len': data_len,
                    'data': data[6:]
                }
                if mdid_cmd == MdidCoreCmd.MDID_CORE_COMMAND_GETREGISTERVALUES:
                    last_command['register_start'] = data[6]
                    last_command['registers'] = data[7]
                pprint(last_command)
                if UpbDeviceId.has_value(destination_id):
                    if UpbDeviceId(destination_id) == UpbDeviceId.BROADCAST_DEVICEID:
                        print('Broadcasting')
                    else:
                        print(f'Have device id type: {UpbDeviceId.BROADCAST_DEVICEID.name}')
        else:
            print(f'Upstart corrupt data line: {line}')

    def data_received(self, data):
        self.buffer += data
        while b'\r' in self.buffer:
            line, self.buffer = self.buffer.split(b'\r', 1)
            if len(line) >= 1:
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
