import json
import sys
import socket
import hashlib
import requests
import struct
import os

#Using the bencodepy library will be much more helpfull in this situation 
#using the (utf-8 formating of "i23e" to decode and encode the binary charecters of our file )
# creating the decode for all strings , int , list , dictionary , etc with different return types 

# now with the functions

def decode_string(bencoded_value):
    """
    Decodes a bencoded string.

    Args:
        bencoded_value (bytes): The bencoded string to decode.

    Returns:
        tuple: A tuple containing the decoded string and the remaining bencoded value.

    Example:
        >>> decode_string(b"5:hello")
        (b'hello', b'')
    """
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Not a string")
    length_string = int(bencoded_value[:first_colon_index])
    decoded_string = bencoded_value[
        first_colon_index + 1 : first_colon_index + 1 + length_string
    ]
    bencoded_remainder = bencoded_value[first_colon_index + 1 + length_string :]
    return decoded_string, bencoded_remainder

def decode_int(bencoded_value):
    """
    Decodes a bencoded integer.

    Args:
        bencoded_value (bytes): The bencoded integer to decode.

    Returns:
        tuple: A tuple containing the decoded integer and the remaining bencoded value.

    Example:
        >>> decode_int(b"i23e")
        (23, b'')
    """
    if chr(bencoded_value[0]) != "i":
        raise ValueError("Not an integer")
    end_int = bencoded_value.find(b"e")
    if end_int == -1:
        raise ValueError("Not an integer")
    decoded_int = int(bencoded_value[1:end_int])
    bencoded_remainder = bencoded_value[end_int + 1 :]
    return decoded_int, bencoded_remainder

def decode_list(bencoded_value):
    """
    Decodes a bencoded list.

    Args:
        bencoded_value (bytes): The bencoded list to decode.

    Returns:
        tuple: A tuple containing the decoded list and the remaining bencoded value.

    Example:
        >>> decode_list(b"li1ei2ei3ee")
        ([1, 2, 3], b'')
    """
    if chr(bencoded_value[0]) != "l":
        raise ValueError("Not a list")
    bencoded_remainder = bencoded_value[1:]
    decoded_list = []
    while chr(bencoded_remainder[0]) != "e":
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_list.append(decoded_value)
    return decoded_list, bencoded_remainder[1:]

def decode_dict(bencoded_value):
    """
    Decodes a bencoded dictionary.

    Args:
        bencoded_value (bytes): The bencoded dictionary to decode.

    Returns:
        tuple: A tuple containing the decoded dictionary and the remaining bencoded value.

    Example:
        >>> decode_dict(b"d3:foo3:bare")
        ({b'foo': b'bar'}, b'')
    """
    if chr(bencoded_value[0]) != "d":
        raise ValueError("Not a dict")
    bencoded_remainder = bencoded_value[1:]
    decoded_dict = {}
    while chr(bencoded_remainder[0]) != "e":
        decoded_key, bencoded_remainder = decode_string(bencoded_remainder)
        decoded_value, bencoded_remainder = decode_bencode(bencoded_remainder)
        decoded_dict[decoded_key.decode()] = decoded_value
    return decoded_dict, bencoded_remainder[1:]

def decode_bencode(bencoded_value):
    """
    Decodes a bencoded value.

    Args:
        bencoded_value (bytes): The bencoded value to decode.

    Returns:
        tuple: A tuple containing the decoded value and the remaining bencoded value.

    Example:
        >>> decode_bencode(b"5:hello")
        (b'hello', b'')
    """
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0]) == "i":
        return decode_int(bencoded_value)
    elif chr(bencoded_value[0]) == "l":
        return decode_list(bencoded_value)
    elif chr(bencoded_value[0]) == "d":
        return decode_dict(bencoded_value)
    else:
        raise NotImplementedError(
            "We only support strings, integers, lists, and dicts."
        )

def bencode_string(unencoded_value):
    """
    Encodes a string as a bencoded string.

    Args:
        unencoded_value (str): The string to encode.

    Returns:
        bytes: The bencoded string.

    Example:
        >>> bencode_string("hello")
        b'5:hello'
    """
    length = len(unencoded_value)
    return (str(length) + ":" + unencoded_value).encode()

def bencode_bytes(unencoded_value):
    """
    Encodes a bytes object as a bencoded string.

    Args:
        unencoded_value (bytes): The bytes object to encode.

    Returns:
        bytes: The bencoded string.

    Example:
        >>> bencode_bytes(b"hello")
        b'5:hello'
    """
    length = len(unencoded_value)
    return str(length).encode() + b":" + unencoded_value

def bencode_int(unencoded_value):
    """
    Encodes an integer as a bencoded integer.

    Args:
        unencoded_value (int): The integer to encode.

    Returns:
        bytes: The bencoded integer.

    Example:
        >>> bencode_int(23)
        b'i23e'
    """
    return ("i" + str(unencoded_value) + "e").encode()

def bencode_list(unencoded_value):
    """
    Encodes a list as a bencoded list.

    Args:
        unencoded_value (list): The list to encode.

    Returns:
        bytes: The bencoded list.

    Example:
        >>> bencode_list([1, 2, 3])
        b'li1ei2ei3ee'
    """
    result = b"l"
    for i in unencoded_value:
        result += bencode(i)
    return result + b"e"

def bencode_dict(unencoded_value):
    """
    Encodes a dictionary as a bencoded dictionary.

    Args:
        unencoded_value (dict): The dictionary to encode.

    Returns:
        bytes: The bencoded dictionary.

    Example:
        >>> bencode_dict({b"foo": b"bar"})
        b'd3:foob3:bare'
    """
    result = b"d"
    for k in unencoded_value:
        result += bencode(k) + bencode(unencoded_value[k])
    return result + b"e"

def bencode(unencoded_value):
    """
    Encodes a value as a bencoded value.

    Args:
        unencoded_value (str, int, list, dict, bytes): The value to encode.

    Returns:
        bytes: The bencoded value.

    Example:
        >>> bencode("hello")
        b'5:hello'
    """
    if isinstance(unencoded_value, str):
        return bencode_string(unencoded_value)
    elif isinstance(unencoded_value, bytes):
        return bencode_bytes(unencoded_value)
    elif isinstance(unencoded_value, int):
        return bencode_int(unencoded_value)
    elif isinstance(unencoded_value, list):
        return bencode_list(unencoded_value)
    elif isinstance(unencoded_value, dict):
        return bencode_dict(unencoded_value)
    else:
        raise ValueError("Can only bencode strings, ints, lists, or dicts.")


def decode_torrentfile(filename):
    """
    Decodes a torrent file and returns the decoded value.

    Args:
        filename (str): The path to the torrent file.

    Returns:
        dict: The decoded torrent file contents.

    Example:
        >>> decode_torrentfile("example.torrent")
        {'announce': b'http://example.com/announce', 'info': {'length': 12345, 'piece length': 16384, ...}}
    """
    with open(filename, "rb") as f:
        bencoded_content = f.read()
        decoded_value, remainder = decode_bencode(bencoded_content)
        if remainder:
            raise ValueError("Undecoded remainder.")
        return decoded_value

def piece_hashes(pieces):
    """
    Splits a piece of hashes into individual hashes.

    Args:
        pieces (bytes): The piece of hashes.

    Returns:
        list: A list of individual hashes.

    Example:
        >>> piece_hashes(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12')
        [b'\x01\x02\x03\x04', b'\x05\x06\x07\x08', b'\x09\x10\x11\x12']
    """
    n = 20
    if len(pieces) % n != 0:
        raise ValueError("Piece hashes do not add up to a multiple of", n, "bytes.")
    return [pieces[i : i + n] for i in range(0, len(pieces), n)]

def print_info(filename):
    """
    Prints information about a torrent file.

    Args:
        filename (str): The path to the torrent file.

    Example:
        >>> print_info("example.torrent")
        Tracker URL: http://example.com/announce
        Length: 12345
        Info Hash: 1234567890abcdef
        Piece Length: 16384
        Piece Hashes:
        01 02 03 04 05 06 07 08
        09 10 11 12 13 14 15 16
    """
    decoded_value = decode_torrentfile(filename)
    print("Tracker URL:", decoded_value["announce"].decode())
    print("Length:", decoded_value["info"]["length"])
    info_hash = hashlib.sha1(bencode(decoded_value["info"])).hexdigest()
    print("Info Hash:", info_hash)
    print("Piece Length:", decoded_value["info"]["piece length"])
    print("Piece Hashes:")
    hashes = piece_hashes(decoded_value["info"]["pieces"])
    for h in hashes:
        print(h.hex())

def get_peers(filename):
    """
    Retrieves a list of peers from a torrent file.

    Args:
        filename (str): The path to the torrent file.

    Returns:
        list: A list of peers.

    Example:
        >>> get_peers("example.torrent")
        [b'\x01\x02\x03\x04\x05\x06', b'\x07\x08\x09\x10\x11\x12']
    """
    decoded_value = decode_torrentfile(filename)
    tracker_url = decoded_value["announce"].decode()
    info_hash = hashlib.sha1(bencode(decoded_value["info"])).digest()
    peer_id = "00112233445566778899"
    port = 6881
    uploaded = 0
    downloaded = 0
    left = decoded_value["info"]["length"]
    compact = 1
    params = dict(
        info_hash=info_hash,
        peer_id=peer_id,
        port=port,
        uploaded=uploaded,
        downloaded=downloaded,
        left=left,
        compact=compact,
    )
    result = requests.get(tracker_url, params=params)
    decoded_result = decode_bencode(result.content)[0]
    return decoded_result["peers"]

def split_peers(peers):
    """
    Splits a list of peers into individual peers.

    Args:
        peers (bytes): The list of peers.

    Returns:
        list: A list of individual peers.

    Example:
        >>> split_peers(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12')
        ['1.2.3.4:5678', '5.6.7.8:9012']
    """
    if len(peers) % 6 != 0:
        raise ValueError(
            "Peer list from tracker does not divide into 6 bytes; did you use compact?"
        )
    uncompacted_peers = []
    for peer in [peers[i : i + 6] for i in range(0, len(peers), 6)]:
        ip = str(peer[0]) + "." + str(peer[1]) + "." + str(peer[2]) + "." + str(peer[3])
        port = str(int.from_bytes(peer[4:], byteorder="big", signed=False))
        uncompacted_peers.append(ip + ":" + port)
    return uncompacted_peers

def init_handshake(filename, peer):
    """
    Initializes a handshake with a BitTorrent peer.

    Args:
        filename (str): The name of the torrent file.
        peer (str): The peer's IP address and port number in the format "ip:port".

    Returns:
        tuple: A tuple containing the socket object and the received handshake message.

    Example:
        >>> s, received_message = init_handshake("example.torrent", "192.168.1.100:6881")
        >>> print(received_message)
    """
    decoded_value = decode_torrentfile(filename)
    peer_colon = peer.find(":")
    ip = peer[:peer_colon]
    port = int(peer[peer_colon + 1:])
    length_prefix = struct.pack(">B", 19)
    protocol_string = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    info_hash = hashlib.sha1(bencode(decoded_value["info"])).digest()
    peer_id = b"00112233445566778899"
    message = length_prefix + protocol_string + reserved_bytes + info_hash + peer_id
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(message)
    # Only grab the first 68 bytes, that's the handshake. Anything after this is the start of the bitfield.
    received_message = s.recv(68)
    return s, received_message

def construct_message(message_id, payload):
    """
    Constructs a BitTorrent message.

    Args:
        message_id (int): The ID of the message.
        payload (bytes): The payload of the message.

    Returns:
        bytes: The constructed message.

    Example:
        >>> message = construct_message(6, b"example payload")
        >>> print(message)
    """
    message_id = message_id.to_bytes(1)
    message = message_id + payload
    length = len(message)
    length_prefix = length.to_bytes(4, byteorder="big")
    message = length_prefix + message
    return message

def verify_message(message, message_id):
    """
    Verifies a BitTorrent message.

    Args:
        message (bytes): The message to verify.
        message_id (int): The expected ID of the message.

    Raises:
        ValueError: If the message ID or length is incorrect.

    Example:
        >>> verify_message(b"\x00\x00\x00\x10\x06example payload", 6)
    """
    if message[4] != message_id:
        raise ValueError(
            "Expected message of id %s, but received id %s" % (message_id, message[4])
        )
    if int.from_bytes(message[:4]) != len(message[4:]):
        raise ValueError("Message wrong length.")

def request_block(s, piece_index, block_index, length):
    """
    Requests a block from a BitTorrent peer.

    Args:
        s (socket): The socket object.
        piece_index (int): The index of the piece.
        block_index (int): The index of the block.
        length (int): The length of the block.

    Returns:
        bytes: The received block.

    Example:
        >>> block = request_block(s, 0, 0, 2**14)
        >>> print(block)
    """
    index = piece_index
    begin = block_index * 2**14
    length = length
    payload = (
        struct.pack(">I", index) + struct.pack(">I", begin) + struct.pack(">I", length)
    )
    message = construct_message(6, payload)
    s.send(message)
    piece_message = receive_message(s)
    while piece_message[4] != 7:
        piece_message = receive_message(s)
    # Verify that the block has the payload we expect:
    verify_message(piece_message, 7)
    received_index = int.from_bytes(piece_message[5:9])
    received_begin = int.from_bytes(piece_message[9:13])
    if received_index != index or received_begin != begin:
        raise ValueError("Piece message does not have expected payload.")
    block = piece_message[13:]
    return block

def receive_message(s):
    """
    Receive a message from a socket.

    This function receives a message from a socket, handling cases where the message is not fully received.

    Args:
        s (socket): The socket to receive the message from.

    Returns:
        bytes: The received message.

    Example:
        >>> import socket
        >>> s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        >>> s.connect(("example.com", 80))
        >>> message = receive_message(s)
        >>> print(message)
    """
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    # If we didn't receive the full message for some reason, keep gobbling.
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message

def download_piece(outputfile, filename, piececount):
    """
    Download a single piece of a torrent file.

    This function downloads a single piece of a torrent file from a peer, verifies its hash, and writes it to disk.

    Args:
        outputfile (str): The file to write the piece to.
        filename (str): The name of the torrent file.
        piececount (int): The index of the piece to download.

    Returns:
        tuple: A tuple containing the piece index and the file path.

    Example:
        >>> download_piece("/tmp/test-0", "example.torrent", 0)
        (0, "/tmp/test-0")
    """
    decoded_value = decode_torrentfile(filename)
    peers = split_peers(get_peers(filename))
    # For the sake of simplicity, at this stage, just use the first peer:
    peer = peers[1]
    s, received_message = init_handshake(filename, peer)
    # Wait for bitfield message:
    # It's only sent once, so no need to do a while here.
    bitfield = receive_message(s)
    verify_message(bitfield, 5)
    # Build and send interested message
    interested = construct_message(2, b"")
    s.send(interested)
    # Wait for unchoke message
    unchoke = receive_message(s)
    while unchoke[4] != 1:
        unchoke = receive_message(s)
    verify_message(unchoke, 1)
    # Calculate number of blocks, figuring out if we are the last piece
    last_piece_remainder = (
        decoded_value["info"]["length"] % decoded_value["info"]["piece length"]
    )
    total_pieces = len(piece_hashes(decoded_value["info"]["pieces"]))
    if piececount + 1 == total_pieces and last_piece_remainder > 0:
        length = last_piece_remainder
    else:
        length = decoded_value["info"]["piece length"]
    block_size = 16 * 1024
    full_blocks = length // block_size
    final_block = length % block_size
    # Send request for a block. This is painfully duplicated at the moment
    # to handle corner case where only have a small block.
    piece = b""
    sha1hash = hashlib.sha1()
    if full_blocks == 0:
        block = request_block(s, piececount, 0, final_block)
        piece += block
        sha1hash.update(block)
    else:
        for i in range(full_blocks):
            block = request_block(s, piececount, i, block_size)
            piece += block
            sha1hash.update(block)
        if final_block > 0:
            block = request_block(s, piececount, i + 1, final_block)
            piece += block
            sha1hash.update(block)
    # Verify piece hash
    piece_hash = piece_hashes(decoded_value["info"]["pieces"])[piececount]
    local_hash = sha1hash.digest()
    if piece_hash != local_hash:
        raise ValueError("Piece hash mismatch.")
    # Write piece to disk
    with open(outputfile, "wb") as piece_file:
        piece_file.write(piece)
    # Clean up
    s.close()
    # Return piece completed and location
    return piececount, outputfile

def download(outputfile, filename):
    """
    Download a torrent file.

    This function downloads a torrent file by downloading each piece and writing it to disk.

    Args:
        outputfile (str): The file to write the torrent to.
        filename (str): The name of the torrent file.

    Returns:
        None

    Example:
        >>> download("example.torrent", "example.torrent")
    """
    decoded_value = decode_torrentfile(filename)
    total_pieces = len(piece_hashes(decoded_value["info"]["pieces"]))
    piecefiles = []
    for piece in range(0, total_pieces):
        p, o = download_piece("/tmp/test-" + str(piece), filename, piece)
        piecefiles.append(o)
    with open(outputfile, "ab") as result_file:
        for piecefile in piecefiles:
            with open(piecefile, "rb") as piece_file:
                result_file.write(piece_file.read())
            os.remove(piecefile)

def bytes_to_str(data):
    """
    Convert bytes to a string.

    This function converts bytes to a string, handling cases where the bytes are not UTF-8 encoded.

    Args:
        data (bytes): The bytes to convert.

    Returns:
        str: The converted string.

    Example:
        >>> bytes_to_str(b"Hello, World!")
        'Hello, World!'
    """
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")

def main():
    """
    The main function.

    This function parses the command line arguments and calls the corresponding function.

    Args:
        None

    Returns:
        None

    Example:
        >>> main()
    """
    command = sys.argv[1]
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoded_value, remainder = decode_bencode(bencoded_value)
        if remainder:
            raise ValueError("Undecoded remainder.")
        print(json.dumps(decoded_value, default=bytes_to_str))
    elif command == "info":
        if len(sys.argv) != 3:
            raise NotImplementedError(f"Usage: {sys.argv[0]} info filename")
        filename = sys.argv[2]
        print_info(filename)
    elif command == "peers":
        if len(sys.argv) != 3:
            raise NotImplementedError(f"Usage: {sys.argv[0]} peers filename")
        filename = sys.argv[2]
        peers = split_peers(get_peers(filename))
        for p in peers:
            print(p)
    elif command == "handshake":
        if len(sys.argv) != 4:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} handshake filename <peer_ip>:<peer_port>"
            )
        filename = sys.argv[2]
        peer = sys.argv[3]
        peer_socket, received_message = init_handshake(filename, peer)
        received_id = received_message[48:68].hex()
        print("Peer ID:", received_id)
        peer_socket.close()
    elif command == "download_piece":
        if len(sys.argv) != 6:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} download_piece -o output filename piececount"
            )
        outputfile = sys.argv[3]
        filename = sys.argv[4]
        piececount = sys.argv[5]
        p, o = download_piece(outputfile, filename, int(piececount))
        print("Piece %i downloaded to %s" % (p, o))
    elif command == "download":
        if len(sys.argv) != 5:
            raise NotImplementedError(
                f"Usage: {sys.argv[0]} download -o output filename"
            )
        outputfile = sys.argv[3]
        filename = sys.argv[4]
        download(outputfile, filename)
        print("Download %s to %s" % (filename, outputfile))
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()


