import asyncio
import sys
import hmac
from pprint import pprint, pformat
from binascii import unhexlify
from struct import unpack

from const import PimCommand, UpbMessage, UpbDeviceId, UpbTransmission, UpbReqAck, UpbReqRepeater, \
MdidSet, MdidCoreCmd, MdidDeviceControlCmd, MdidCoreReport, GatewayCmd, \
UPB_MESSAGE_TYPE, UPB_MESSAGE_PIMREPORT_TYPE, INITIAL_PIM_REG_QUERY_BASE, PACKETHEADER_LINKBIT, PULSE_REPORT_BYTES
from util import cksum, hexdump

class PIM(asyncio.Protocol):

    def __init__(self):
        self.server_transport = None
        self.buffer = b''
        self.last_command = {}
        self.message_buffer = b''
        self.pim_accept = False
        self.transmitted = False
        self.upb_packet = bytearray(64)
        self.pulse_data_seq = 0
        self.packet_byte = 0
        self.packet_crumb = 0
        self.data_counter = 0
        self.protocol = None
        self.initial = True
        self.challenge = None
        self.authenticated = False
        self.wrapped = False
        self.pim_info = {}

    def connection_made(self, transport):
        print("connected to PIM")
        self.initial = True
        self.challenge = None
        self.authenticated = False
        self.wrapped = False
        self.pim_info = {}
        self.connected = True
        self.transport = transport

    def set_state_zero(self):
        self.transmitted = False
        self.pulse_data_seq = 0
        self.packet_crumb = 0
        self.packet_byte = 0

    def process_packet(self, packet):
        control_word = packet[0:2]
        data_len = (control_word[0] & 0x1f) - 6
        transmit_cnt = control_word[1] & 0x0c >> 2
        transmit_seq = control_word[1] & 0x03
        network_id = packet[2]
        destination_id = packet[3]
        source_id = packet[4]
        mdid_set = MdidSet(packet[5] & 0xe0)
        if mdid_set == MdidSet.MDID_CORE_COMMANDS:
            mdid_cmd = MdidCoreCmd(packet[5] & 0x1f)
        elif mdid_set == MdidSet.MDID_DEVICE_CONTROL_COMMANDS:
            mdid_cmd = MdidDeviceControlCmd(packet[5] & 0x1f)
        elif mdid_set == MdidSet.MDID_CORE_REPORTS:
            mdid_cmd = MdidCoreReport(packet[5] & 0x1f)
        crc = packet[data_len + 5]
        computed_crc = cksum(packet[0:data_len + 5])
        assert(crc == computed_crc)
        response = {
            'transmit_cnt': transmit_cnt,
            'transmit_seq': transmit_seq,
            'network_id': network_id,
            'destination_id': destination_id,
            'device_id': source_id,
            'mdid_set': mdid_set,
            'mdid_cmd': mdid_cmd
        }
        if mdid_cmd == MdidCoreReport.MDID_DEVICE_CORE_REPORT_REGISTERVALUES:
            response['setup_register'] = packet[6]
            response['register_val'] = packet[7:data_len + 5]
            for index in range(len(response['register_val'])):
                print(f"Reg index: {index}, value: {hex(response['register_val'][index])}")
        else:
            response['data'] = packet[6:data_len + 5]
        pprint(response)

    def nt_line_received(self, line):
        print(f'pim null terminated line: {line}, hex: {hexdump(line)}')
        errors = {
            'MAX CONNECTIONS REACHED',
            'PULSE MODE ACTIVE',
            'PIM NOT INITIALIZED',
            'FIRMWARE CORRUPT - FLASH WITH UPSTART'
        }
        if self.initial and self.authenticated:
            result, client = line.split(b'/', maxsplit=1)
            if result == b'AUTHENTICATION FAILED':
                print("auth failed")
            elif result == b'AUTH SUCCEEDED':
                print("auth succeded")
                self.initial = False
                self.wrapped = True
            else:
                print(f"unexpected auth result: {result}")
        elif self.initial:
            if line in errors or len(line) < 12:
                print(f"unhandled error: {line}")
                return
            prefix, version, protocol, auth, suffix = line.split(b'/', maxsplit=4)
            majorVersion, minorVersion = version.split(b'.', maxsplit=1)
            assert(self.protocol == protocol)
            self.pim_info = {
                'prefix': prefix,
                'version': version,
                'protocol': protocol,
                'auth': auth,
                'majorVersion': majorVersion,
                'minorVersion': minorVersion
            }
            self.challenge = unhexlify(suffix)
            print(f'self.pim_info:\n{pformat(self.pim_info)}')

    def line_received(self, line):
        print(f'pim line: {line}')
        if UpbMessage.has_value(line[UPB_MESSAGE_TYPE]):
            command = UpbMessage(line[UPB_MESSAGE_TYPE])
            data = line[1:]
            if command != UpbMessage.UPB_MESSAGE_IDLE and \
            command != UpbMessage.UPB_MESSAGE_TRANSMITTED and \
            not UpbMessage.is_message_data(command):
                print(f"PIM {command.name} data: {data}")
            if command == UpbMessage.UPB_MESSAGE_IDLE:
                assert(self.packet_byte == 0)
                assert(self.pulse_data_seq == 0)
                assert(self.packet_crumb == 0)
                self.set_state_zero()
            elif command == UpbMessage.UPB_MESSAGE_DROP:
                print('dropped message')
                self.set_state_zero()
            elif command == UpbMessage.UPB_MESSAGE_PIMREPORT:
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
                    elif transmission == UpbTransmission.UPB_PIM_ACCEPT:
                        self.pim_accept = True
                        print("got pim accept")
                else:
                    print(f'got corrupt pim report: {hex(line[UPB_MESSAGE_PIMREPORT_TYPE])} with len: {len(line)}')

            elif command == UpbMessage.UPB_MESSAGE_SYNC:
                self.packet_byte = 0
                self.packet_crumb = 0
            elif command == UpbMessage.UPB_MESSAGE_START:
                self.packet_byte = 0
                self.packet_crumb = 0
            elif UpbMessage.is_message_data(command):
                self.data_counter += 1
                if len(data) == 2:
                    seq = unhexlify(b'0' + data[1:2])[0]
                    two_bits = command.value - 0x30
                    assert(seq == self.pulse_data_seq)
                    if seq == self.pulse_data_seq:
                        if self.packet_crumb == 0:
                            self.upb_packet[self.packet_byte] = (two_bits << 6)
                            self.packet_crumb += 1
                        elif self.packet_crumb == 1:
                            self.upb_packet[self.packet_byte] |= (two_bits << 4)
                            self.packet_crumb += 1
                        elif self.packet_crumb == 2:
                            self.upb_packet[self.packet_byte] |= (two_bits << 2)
                            self.packet_crumb += 1
                        elif self.packet_crumb == 3:
                            self.upb_packet[self.packet_byte] |= two_bits
                            self.packet_crumb = 0
                            self.packet_byte += 1
                        self.pulse_data_seq += 1
                        if self.pulse_data_seq > 0x0f:
                            self.pulse_data_seq = 0
                    else:
                        print(f"Got upb message data bad seq: {hex(self.seq)}")

            elif command == UpbMessage.UPB_MESSAGE_TRANSMITTED:
                self.transmitted = True
                if len(data) == 2:
                    seq = unhexlify(b'0' + data[1:2])[0]
                    two_bits = data[0] - 0x30
                    assert(seq == self.pulse_data_seq)
                    if seq == self.pulse_data_seq:
                        if self.packet_crumb == 0:
                            self.upb_packet[self.packet_byte] = (two_bits << 6)
                            self.packet_crumb += 1
                        elif self.packet_crumb == 1:
                            self.upb_packet[self.packet_byte] |= (two_bits << 4)
                            self.packet_crumb += 1
                        elif self.packet_crumb == 2:
                            self.upb_packet[self.packet_byte] |= (two_bits << 2)
                            self.packet_crumb += 1
                        elif self.packet_crumb == 3:
                            self.upb_packet[self.packet_byte] |= two_bits
                            self.packet_crumb = 0
                            self.packet_byte += 1
                        self.pulse_data_seq += 1
                        if self.pulse_data_seq > 0x0f:
                            self.pulse_data_seq = 0
                    else:
                        print(f"Got upb message data bad seq: {hex(self.seq)}")
            elif command == UpbMessage.UPB_MESSAGE_ACK or command == UpbMessage.UPB_MESSAGE_NAK:
                if self.transmitted:
                    self.message_buffer = bytes(self.upb_packet[1:self.packet_byte - 1])
                else:
                    self.message_buffer = bytes(self.upb_packet[0:self.packet_byte])
                    if len(self.message_buffer) != 0:
                        self.process_packet(self.message_buffer)
                if self.transmitted and len(self.message_buffer) != 0:
                    print(f"Got upb pim message data: {self.message_buffer}")
                elif len(self.message_buffer) != 0:
                    print(f"Got upb message data: {self.message_buffer}")
                if len(self.message_buffer) != 0:
                    if self.last_command.get('mdid_cmd', None) == MdidCoreCmd.MDID_CORE_COMMAND_GETDEVICESIGNATURE:
                        print(f"Decoding signature with length {len(self.message_buffer)}")
                        for index in range(len(self.message_buffer)):
                            print(f"Reg index: {index}, value: {hex(self.message_buffer[index])}")
                self.message_buffer = b''
                self.data_counter = 0
                if self.packet_byte > 0:
                    self.set_state_zero()
        else:
            print(f'PIM failed to parse line: {line}')

    def data_received(self, data):
        self.buffer += data
        #print(f'pim buffer: {self.buffer}, hex: {hexdump(self.buffer)}')
        if self.server_transport:
            self.server_transport.write(data)
        if self.wrapped:
            while len(self.buffer) > 0 and GatewayCmd.has_value(self.buffer[0]-1):
                if len(self.buffer) >= 8:
                    rcCommand = self.buffer[1]
                    assert(rcCommand == 0x00)
                    length = unpack('>H', self.buffer[6:8])[0]
                    #print(f"pim length: {length}")
                    if len(self.buffer) >= length + 9:
                        cmd = GatewayCmd(self.buffer[0]-1)
                        #print(f"pim cmd: {cmd.name}")
                        if cmd == GatewayCmd.SEND_TO_SERIAL:
                            line = self.buffer[8:length+7]
                            self.buffer = self.buffer[length+10:]
                            #print(f"pim gateway response: {line}, hex: {hexdump(line)} length: {length}")
                            self.line_received(line)
                        elif cmd == GatewayCmd.KEEP_ALIVE:
                            self.buffer = self.buffer[length+4:]
                    else:
                        return
                else:
                    return
        else:
            while b'\x00' in self.buffer:
                line, self.buffer = self.buffer.split(b'\x00', 1)
                if len(line) >= 1:
                    self.nt_line_received(line)
            while b'\r' in self.buffer and not self.wrapped:
                line, self.buffer = self.buffer.split(b'\r', 1)
                if len(line) > 1:
                    self.line_received(line)

    def connection_lost(self, *args):
        print("pim connection lost")
        self.connected = False

class Upstart(asyncio.Protocol):

    def __init__(self, transport, protocol, username=None, password=None):
        self.client = protocol
        self.initial = False
        self.client_info = {}
        self.buffer = b''
        self.username = username
        self.password = password

    def connection_made(self, transport):
        print("Upstart connected")
        # save the transport
        self.initial = True
        self.client_info = {}
        self.client.protocol = None
        self.transport = transport
        self.client.server_transport = self.transport

    def send_data(self, data):
        self.client.transport.write(data)

    def nt_line_received(self, line):
        print(f'upstart null terminated line: {line}, hex: {hexdump(line)}')
        if self.initial:
            if self.client.pim_info.get('auth', None) == b'AUTH REQUIRED' and \
                self.client.challenge is not None and self.client.authenticated is not True:
                assert(len(self.client.challenge) == 64)
                gatewayUserName, gatewayPasswordHash = line.split(b'/', maxsplit=1)
                assert(self.username.encode('utf-8') == gatewayUserName)
                digest = hmac.new(self.password.encode('utf-8'), self.client.challenge, 'md5').hexdigest().swapcase().encode('ascii')
                assert(digest == gatewayPasswordHash)
                self.client_info['gatewayUserName'] = self.username
                self.client_info['gatewayPassword'] = self.password
                self.client.authenticated = True
            elif self.client.authenticated is not True:
                prefix, version, protocol = line.split(b'/', maxsplit=2)
                majorVersion, minorVersion, buildNumber = version.split(b'.', maxsplit=2)
                self.client_info = {
                    'prefix': prefix,
                    'version': version,
                    'protocol': protocol,
                    'majorVersion': majorVersion,
                    'minorVersion': minorVersion,
                    'buildNumber': buildNumber
                }
                self.client.protocol = protocol
            print(f'self.client_info:\n{pformat(self.client_info)}')

    def line_received(self, line):
        #print(f'upstart line: {line}')
        command = PimCommand(line[0])
        data = unhexlify(line[1:-2])
        crc = int(line[-2:], 16)
        computed_crc = cksum(data)
        if crc == computed_crc:
            print(f'Upstart {command.name} line: {line}, data: {data}')
            if command == PimCommand.UPB_NETWORK_TRANSMIT:
                control_word = data[0:2]
                link_bit = (control_word[0] >> PACKETHEADER_LINKBIT) & 7
                repeater_request = UpbReqRepeater((control_word[0] >> 0x60) & 5)
                data_len = control_word[0] & 0x1f
                assert(data_len == len(data) + 1)
                reserved = control_word[1] & 0x80 >> 7
                assert(reserved == 0x00)
                ack_request = UpbReqAck((control_word[1] >> 0x70) & 4)
                transmit_cnt = (control_word[1] >> 0x0c) & 2
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
                    'data_len': data_len
                }
                if mdid_cmd == MdidCoreCmd.MDID_CORE_COMMAND_GETREGISTERVALUES:
                    last_command['register_start'] = data[6]
                    last_command['registers'] = data[7]
                    last_command['data'] = data[8:]
                else:
                    last_command['data'] = data[6:]
                self.client.last_command = last_command
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
        #print(f'upstart buffer: {self.buffer}, hex: {hexdump(self.buffer)}')
        self.send_data(data)
        if self.client.wrapped:
            while len(self.buffer) > 0 and GatewayCmd.has_value(self.buffer[0]):
                if len(self.buffer) >= 4:
                    length = unpack('>H', self.buffer[1:3])[0]
                    if len(self.buffer) > length + 4:
                        #print(f"length: {length}")
                        cmd = GatewayCmd(self.buffer[0])
                        #print(f"cmd: {cmd.name}")
                        if cmd == GatewayCmd.SEND_TO_SERIAL:
                            line = self.buffer[3:length+2]
                            self.buffer = self.buffer[length+4:]
                            #print(f"gateway to serial line: {line}, hex: {hexdump(line)} length: {length}")
                            self.line_received(line)
                        elif cmd == GatewayCmd.KEEP_ALIVE:
                            self.buffer = self.buffer[length+4:]
                    else:
                        return
                else:
                    return
        else:
            while b'\x00' in self.buffer:
                line, self.buffer = self.buffer.split(b'\x00', 1)
                if len(line) > 0:
                    self.nt_line_received(line)
            while b'\r' in self.buffer and not self.client.wrapped:
                line, self.buffer = self.buffer.split(b'\r', 1)
                if len(line) >= 1:
                    self.line_received(line)

    def connection_lost(self, *args):
        print("upstart connection lost")
        self.initial = False
        self.client.server_transport = None

async def main():
    loop = asyncio.get_event_loop()

    client_t, client_p = await loop.create_connection(PIM, sys.argv[1], int(sys.argv[2]))

    if len(sys.argv) > 3:
        server = await loop.create_server(lambda: Upstart(client_t, client_p, sys.argv[3], sys.argv[4]), '0.0.0.0', 2101)
    else:
        server = await loop.create_server(lambda: Upstart(client_t, client_p), '0.0.0.0', 2101)
    async with server:
        await server.serve_forever()

asyncio.run(main())
