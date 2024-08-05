def transmission_delay(packet_length_bytes, rate_gbps):
    r = rate_gbps
    l = packet_length_bytes

    delay = l * 8
    r_to_bits = r * 1000000000

    return (delay / r_to_bits) * 1000


def total_time(cable_length_km, packet_length_b):
    d = cable_length_km
    l = packet_length_b

    transdelay = transmission_delay(l, 10)
    propagation_delay = d/200000

    return propagation_delay + transdelay 


import math

def total_number_bits(max_user_data_per_packet_b, overhead_per_packet_b, message_length_b):
    s = max_user_data_per_packet_b
    o = overhead_per_packet_b
    m = message_length_b

    number_of_packages = math.ceil(m / s)

    added_overhead = o * number_of_packages

    total = added_overhead + m


    return total



def packet_transfer_time(link_length_km, light_speed_kmps, processing_delay_s, data_rate_bps, max_user_data_per_packet_b, overhead_per_packet_b):
    d = link_length_km
    c = light_speed_kmps
    p = processing_delay_s
    r = data_rate_bps
    s = max_user_data_per_packet_b
    o = overhead_per_packet_b



    propagation = d/c
    transmission_delay = (s+o) / r

    total = (propagation * 2) + (p*2) + transmission_delay * 2

    return total





def total_transfer_time(link_length_km, light_speed_kmps, processing_delay_s, data_rate_bps, max_user_data_per_packet_b, overhead_per_packet_b, message_length_b):
    d = link_length_km
    c = light_speed_kmps
    p = processing_delay_s
    r = data_rate_bps
    s = max_user_data_per_packet_b
    o = overhead_per_packet_b
    m = message_length_b

    num_of_packets = m // s
    propagation = d/c
    transmission = (s+o) / r

    total = (propagation * 2) + (p * 2) + (transmission * (num_of_packets + 1))


    return total




def compose_header(version, hdrlen, tosdscp, totallength, identification, flags, fragmentoffset, timetolive, protocoltype, headerchecksum, sourceaddress, destinationaddress):
    """Takes the values to be filled into the IPv4 header
       and returns a 20-byte bytearray of the standard IPv4 header.
       Raises an appropriate ValueError if a parameter is erroneous.
    """
        
    if version != 4:
        raise ValueError("version field must be 4")
    if hdrlen > 15 or hdrlen < 0:
        raise ValueError("hdrlen value cannot fit in 4 bits")
    if tosdscp > 63 or tosdscp < 0:
        raise ValueError("tosdscp value cannot fit in 6 bits")
    if totallength > 65535 or totallength < 0:
        raise ValueError("totallength value cannot fit in 16 bits")
    if identification > 65535 or identification < 0:
        raise ValueError("identification value cannot fit in 16 bits")
    if flags > 7 or flags < 0:
        raise ValueError("flags value cannot fit in 3 bits")
    if fragmentoffset > 8191 or fragmentoffset < 0:
        raise ValueError("fragmentoffset value cannot fit in 13 bits")
    if timetolive > 255 or timetolive < 0:
        raise ValueError("timetolive value cannot fit in 8 bits")
    if protocoltype > 255 or protocoltype < 0:
        raise ValueError("protocoltype value cannot fit in 8 bits")
    if headerchecksum > 65535 or headerchecksum < 0:
        raise ValueError("headerchecksum value cannot fit in 16 bits")
    if sourceaddress > 4294967295 or sourceaddress < 0:
        raise ValueError("sourceaddress value cannot fit in 32 bits")
    elif destinationaddress > 4294967295 or destinationaddress < 0:
        raise ValueError("destinationaddress value cannot fit in 32 bits")
    

    my_array = bytearray()
    my_array.extend(
        [(version << 4) | hdrlen,
         (tosdscp << 2),
         (totallength >> 8) & 0xFF,
         totallength & 0xFF,
         (identification >> 8) & 0xFF,
         identification & 0xFF,
         (flags << 5) | (fragmentoffset >> 8) & 0xFF,
         fragmentoffset & 0xFF,
         timetolive,
         protocoltype,
         (headerchecksum >> 8) & 0xFF,
         headerchecksum & 0xFF,
         (sourceaddress >> 24) & 0xFF,
         (sourceaddress >> 16) & 0xFF,
         (sourceaddress >> 8) & 0xFF,
         sourceaddress & 0xFF,
         (destinationaddress >> 24) & 0xFF,
         (destinationaddress >> 16) & 0xFF,
         (destinationaddress >> 8) & 0xFF,
         destinationaddress & 0xFF,
        ])

    return my_array


def checksum(header):
    """Takes a single bytearray parameter (representing an IPv4 header) 
       and returns the header checksum.
    """
    if len(header) < 20:
        raise ValueError("Header is too short")
    if len(header) % 4 != 0:
        raise ValueError("Header does not contain a multiple of 4 bytes")


    final = 0
    for i in range(0, len(header), 2 ):
        higher = header[i]
        lower = header[i + 1]
        full = (higher << 8) + lower
        final += full
    
    while final > 0xFFFF:
        lowest16 = final & 0xFFFF
        carry = final >> 16
        final = lowest16 + carry

    final = (~final) & 0xFFFF
    return final




# Don't forget to include the definition for the checksum function that you
# wrote for the previous question here!

def basic_packet_check(packet):
    """Takes a single bytearray parameter (representing an IPv4 packet)
       and returns True if it passes all the basic correctness checks.
       Raises an appropriate ValueError if any of the correctness checks fail.
    """
    if len(packet) < 20:
        raise ValueError("Packet does not contain a full IP header")
    
    if packet[0] >> 4 != 4:
        raise ValueError("Packet version number must equal 4")
    
    if (packet[0] & 0x0F) < 5:
        raise ValueError("Packet hdrlen field must be at least 5")

    header_length = (packet[0] & 0x0F) * 4
    ip_header = packet[:header_length]
    if checksum(ip_header) != 0:
        raise ValueError("Packet checksum failed")
    
    total_length = (packet[2] << 8) + packet[3]
    if total_length != len(packet):
        raise ValueError("Packet totallength field is inconsistent with the packet length")
    
    return True



def destination_address(packet):
    """Takes a single bytearray parameter (representing an IPv4 packet)
       and returns a tuple (addr, dd), where: 
       - addr is the 32-bit value of the destination address
       - dd is a string in dotted decimal notation.
    """
    packet = packet[16:20]
    addr = (packet[0] << 24 | packet[1] << 16| packet[2] << 8 | packet[3]) # Weird FR
    dd = f"{packet[0]}.{packet[1]}.{packet[2]}.{packet[3]}"
        
    return addr, dd


def payload(packet):
    """Takes a single bytearray parameter (representing an IPv4 packet)
       and returns just the packet's payload (as a bytearray).
    """
    header_length = (packet[0] & 0x0F) * 4
    payload = packet[header_length:]

    return payload



# Don't forget to include the definition for the checksum function that you
# wrote for the previous question here!

def compose_packet(hdrlen, tosdscp, identification, flags, fragmentoffset, timetolive, protocoltype, sourceaddress, destinationaddress, payload):
    """Takes the values to be filled into the IPv4 header
       and also a bytearray containing the payload.
       Returns a bytearray of the entire IPv4 packet (header and payload).
       Raises an appropriate ValueError if a parameter is erroneous.
    """
    if hdrlen < 5 or hdrlen > 15:
        raise ValueError("hdrlen must be at least 5 and no greater than 15")

    if tosdscp > 63 or tosdscp < 0:
        raise ValueError("tosdscp value cannot fit in 6 bits")
    if identification > 65535 or identification < 0:
        raise ValueError("identification value cannot fit in 16 bits")
    if flags > 7 or flags < 0:
        raise ValueError("flags value cannot fit in 3 bits")
    if fragmentoffset > 8191 or fragmentoffset < 0:
        raise ValueError("fragmentoffset value cannot fit in 13 bits")
    if timetolive > 255 or timetolive < 0:
        raise ValueError("timetolive value cannot fit in 8 bits")
    if protocoltype > 255 or protocoltype < 0:
        raise ValueError("protocoltype value cannot fit in 8 bits")
    if sourceaddress > 4294967295 or sourceaddress < 0:
        raise ValueError("sourceaddress value cannot fit in 32 bits")
    elif destinationaddress > 4294967295 or destinationaddress < 0:
        raise ValueError("destinationaddress value cannot fit in 32 bits")
    

    header_length = (hdrlen) * 4
    payload_len = len(payload)
    totallength = header_length + payload_len

    my_array = bytearray()
    my_array.extend(
        [(4 << 4) | hdrlen,
        (tosdscp << 2),
        (totallength >> 8) & 0xFF,
        totallength & 0xFF,
        (identification >> 8) & 0xFF,
        identification & 0xFF,
        (flags << 5) | (fragmentoffset >> 8) & 0xFF,
        fragmentoffset & 0xFF,
        timetolive,
        protocoltype,
        0,
        0,
        # (the_check >> 8) & 0xFF,
        # the_check & 0xFF,
        # (headerchecksum >> 8) & 0xFF,
        #  headerchecksum & 0xFF,
        (sourceaddress >> 24) & 0xFF,
        (sourceaddress >> 16) & 0xFF,
        (sourceaddress >> 8) & 0xFF,
        sourceaddress & 0xFF,
        (destinationaddress >> 24) & 0xFF,
        (destinationaddress >> 16) & 0xFF,
        (destinationaddress >> 8) & 0xFF,
        destinationaddress & 0xFF,
        
        ])
    
    copy = my_array
    checking = checksum(copy)
    copy[10] = (checking >> 8) & 0xFF
    copy[11] = checking & 0xFF
   
    padding_length = header_length - 20
    copy[20:20+padding_length] = bytearray(padding_length)

    return copy + payload



packet = compose_packet(6, 24, 4711, 0, 22, 64, 0x06, 0x22334455, 0x66778899, bytearray([0x10, 0x11, 0x12, 0x13, 0x14, 0x15]))
print(packet.hex())