import sys
import struct
import copy
from collections import namedtuple
from ipfixd_app.ipfixd_log import log

exit_code = 0

def set_exit( code ):

    global exit_code

    if code > exit_code:
        exit_code = code

def get_exit():
    return( exit_code )

def make_pack_items( l, network_byte_order=True ):

    """
    This function is used to make the pack/unpack items for
    an object.  Since we are almost always looking at unsigned
    values, we do not really have a way to express a signed pack.
    However, this routine should only be called when parsing
    templates or module startup.  So, it would be reasonable to
    look field names if need be.

    Args:
        l: The list of fields to convert.  Each element in the list
            is an indexable item, with 0 being the name and 1 having
            the number of bytes in the field.
        network_byte_order: If True, emit a pack string for network
            byte order, else a native unaligned pack string.

    Returns:
        A tuple of:

        0: A class Struct object that can be used to pack or
            unpack objects
        1: A dict of field names to indexes in the Struct pack
           or unpack iterable.
    """

    if network_byte_order:
        pack_string = '!'
    else:
        pack_string = '='

    d = {}
    field_cnt = 0
    for (i,f) in enumerate(l):
        if f[ 0 ] == 'paddingOctets':
            pack_string += 'x' * f[1]
            continue
        elif f[ 1 ] == 1:
            pack_string += 'B'
        elif f[ 1 ] == 2:
            pack_string += 'H'
        elif f[ 1 ] == 4:
            pack_string += 'L'
        elif f[ 1 ] == 8:
            pack_string += 'Q'
        elif f[ 1 ] > 8:
            pack_string += str(f[1]) + 's'
        else:
            raise ValueError

        d[f[0]]=field_cnt
        field_cnt += 1

    the_struct = struct.Struct( pack_string )

    return( the_struct, d )

def get_fmt_len( c ):

    """
    Returns the length for a given format character.
    """

    if c == 'x' or c == 'b' or c == 'B':
        return( 1 )
    elif c == 'H' or c == 'h':
        return( 2 )
    elif c == 'i' or c == 'I' or c == 'l' or c == 'L':
        return( 4 )
    elif c == 'q' or c == 'Q':
        return( 8 )
    else:
        raise( ValueError( 'Unknown struct format character %s' % c ) )

def make_byte_moves( input_struct, input_keys, output_struct, output_keys ):

    """
    This routine is used to construct a series of byte moves that will
    convert input_struct (assumed to be in network byte order) to
    the output structure, assumed to be little endian.  We really need
    to write some code to figure out if Python is big or little on
    the given system.

    If the input fields match by name, but not by length, and
    the output field is shorter, which is typically the case,
    then the input byte indexes are added to 'check_for_zero'.
    The user of this data should check to make sure that the input
    bytes so listed are zero or else data truncation will occur.

    Note that if the output field is larger, we should be OK
    because the output buffer is usually zeroed to start with.

    Args:
        input_struct: A struct type for input
        input_keys: A dict, keyed by input keys, data item index
        output_struct: A struct type for output
        output_keys: A dict, keyed by output keys, data index index

    Returns:
        input: Array of input byte indexes to move
        output: Array of byte indexes to receive data

        for ( i, o ) in zip( input, output ):
            output[ o ] = input[ i ]

        in_data: A dict, keyed by item key, value is dict with possible
            keys:
                index: Index of the ouput in input
                byte_offset: Offset to item by byte
                len: Length of the item
        out_data; Same as input, but for output
        check_for_zero: Should be run on input to verify high order
            bytes being skipped are zero.  A list of byte indexes to
            check.
    """

    in_data = { k: { 'index': i } for ( k, i ) in input_keys.items() }
    in_data_by_index = { i: k  for ( k, i ) in input_keys.items() }
    out_data = { k: { 'index': i } for ( k, i ) in output_keys.items() }
    out_data_by_index = { i: k for ( k, i ) in output_keys.items() }

    """
    For each format character for the structure, look up the field
    name by index and add byte_offset and length fields to the
    dict associated with the field name.
    """

    for ( format, data_by_index, data ) in [
            ( input_struct.format, in_data_by_index, in_data ),
            ( output_struct.format, out_data_by_index, out_data ) ]:

        byte_offset = 0
        field_index = 0
        for c in format:
            if c == '!' or c == '=':
                continue
            len = get_fmt_len( c )
            if c == 'x':                # Padding, no field.
                byte_offset += len
            else:
                k = data_by_index[ field_index ]
                data[ k ][ 'byte_offset' ] = byte_offset
                data[ k ][ 'len' ] = len
                byte_offset += len
                field_index += 1

    """
    Create a list of tuples that move bytes.  The first member of the
    tuple is the input byte index and the second member, the output
    index.
    """

    input = []
    output = []
    check_for_zero = []

    for ( k, out_info ) in out_data.items():    # For all output
        try:
            in_info = in_data[ k ]              # Exist in input?
        except KeyError:
            log().info( 'INFO: KEY %s not in input' % k )
            continue                            # No

        try:
            if in_info[ 'len' ] != out_info[ 'len' ]:
                log().info( 'WARNING: Key: %s, in len: %d, out len: %d' %
                                    (k, in_info[ 'len' ], out_info[ 'len' ] ))
                in_len = in_info[ 'len' ]
                out_len = out_info[ 'len' ]
                len = min( [ in_len, out_len ] )
                if in_len > out_len:
                    in_skip = in_len - out_len  # Skipping high order bytes
                else:
                    in_skip = 0
            else:
                len = in_info[ 'len' ]
                in_skip = 0
        except KeyError:
            continue

        if in_skip > 0:
            for i in range( in_skip ):
                check_for_zero.append( in_info[ 'byte_offset' ] + i )

        if len == 1:
            input.append( in_info['byte_offset'] );
            output.append( out_info[ 'byte_offset'] )
        elif len == 2:
            for i in range( 1, -1, -1 ):
                input.append( in_skip + in_info[ 'byte_offset' ] + i )
            for i in range( 0, 2, 1 ):
                output.append( out_info[ 'byte_offset' ] + i )
        elif len == 4:
            for i in range( 3, -1, -1 ):
                input.append( in_skip + in_info[ 'byte_offset' ] + i )
            for i in range( 0, 4, 1 ):
                output.append( out_info[ 'byte_offset' ] + i )
        elif len == 8:
            for i in range( 7, -1, -1 ):
                input.append( in_skip + in_info[ 'byte_offset' ] + i )
            for i in range( 0, 8, 1 ):
                output.append( out_info[ 'byte_offset' ] + i )

    return( input, output, in_data, out_data, check_for_zero )

def find_non_zero_bytes( template, buff ):

    """
    This routine is used to find the non-zero bytes in the input
    buffer.  We then create a useful error message that lists the
    field and its information.  We then modify the check_for_zero
    array on the ByteMover object and remove the checks since
    we've output an error message.

    Args:
        template: The template used to process the data
        buff: The buffer with a non-zero byte
    """

    bm = template[ 'byte_mover' ]
    offset = bm.in_offset

    while offset + bm.in_len <= len( buff ):
        new_check_for_zero = []
        for (z_index, z) in enumerate( bm.check_for_zero ):
            if buff[ offset + z ]:
                for ( field_name, field_len, field_offset ) in (
                                            template[ 'field_list' ]):
                    if z >= field_offset and z < field_offset + field_len:
                        log().error( 'ERROR: Stream "%s", field "%s", '
                            'offset %d, length %d at offset %d '
                            'overflows when converting to cflowd' %
                            ( template[ 'key' ], field_name,
                            field_offset, field_len, z ) )
            else:
                new_check_for_zero.append( z )
        bm.check_for_zero = new_check_for_zero
        offset += bm.in_len

# End.
