"""
Module: resolver

A program used to perform iterative DNS queries for A or MX records.
"""
import random
import socket
from struct import pack, unpack
from argparse import ArgumentParser
from typing import Optional
import logging
from random import randrange
import tldextract


from helpers import *


def parse_record(response: bytes, start_index: int) -> tuple[DNSRecord,int]:
    """
    Creates a DNS record form the data in response starting at the given
    index, along with the index where the record's info ends.

    Args:
        response (bytes): The response that will contain the record.
        start_index (int): The location in the response where the record starts.

    Return:
        tuple[DNSRecord,int]: A tuple containing the DNS record that was found
        starting at index, and the index immediately after the end of that
        record.
    """        
    try:
                name, position = decode_dns_name(response, start_index)
                rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', response[position:position + 10])
                rdata_start = position + 10
                rdata_end = rdata_start + rdlength

                if rtype == DNSRecordType.A.value:
                    ip_address = struct.unpack('!BBBB', response[rdata_start:rdata_end])
                    record = DNSRecord(name, DNSRecordType.A, list(ip_address))

                elif rtype == DNSRecordType.NS.value:
                    ns_name, _ = decode_dns_name(response, rdata_start)  # Use rdata_start
                    record = DNSRecord(name, DNSRecordType.NS, ns_name)

                elif rtype == DNSRecordType.MX.value:
                    preference, = struct.unpack('!H', response[rdata_start:rdata_start + 2]) #2bytes
                    exchange_name, next_position = decode_dns_name(response, rdata_start + 2)
                    record = DNSRecord(name, DNSRecordType.MX, exchange_name)# only include the mail exchange domain name in DNSRecord value
                    rdata_end = next_position  # Update the end position after processing the MX record.

                elif rtype == DNSRecordType.SOA.value:
                    mname, offset = decode_dns_name(response, rdata_start)
                    rname, offset = decode_dns_name(response, offset)
                    # The rest of the SOA record fields (serial, refresh, retry, expire, minimum)
                    serial, refresh, retry, expire, minimum = struct.unpack('!5I', response[offset:offset + 20])

                    simplified_soa_value = mname  # This simplification is for test alignment purposes
                    record = DNSRecord(name, DNSRecordType.SOA, simplified_soa_value)

                    rdata_end = offset + 20  # Update the end position after processing the SOA record

                elif rtype == DNSRecordType.CNAME.value:
                    cname, _ = decode_dns_name(response, rdata_start)  # Use rdata_start
                    record = DNSRecord(name, DNSRecordType.CNAME, cname)

                elif rtype == DNSRecordType.AAAA.value:
                    ipv6_address_bytes = response[rdata_start:rdata_end] # 16bytes
                    ipv6_address_integers = [int(b) for b in ipv6_address_bytes]
                    record = DNSRecord(name, DNSRecordType.AAAA, ipv6_address_integers)
                    rdata_end = rdata_start + 16  # always 16 bytes

                else:
                    # Placeholder for unsupported record types
                    record = DNSRecord(name, DNSRecordType(rtype), "Unsupported record type")

                return record, rdata_end
    except Exception as e:
        logging.error(f"Failed to parse DNS record: {e}")
        placeholder_record = DNSRecord("error", DNSRecordType(0), "Parse error")
        return placeholder_record, start_index


def parse_response(response: bytes, expected_query_id: int) -> Optional[DNSResponse]:
    """
    Parses the given response, returning a DNSResponse object containing all
    the answer, authority, and additional records. If response's ID doesn't
    match the expected ID, then return None.

    Args:
        response (bytes): The response to parse
        expected_query_id (int): The ID of the original query.

    Returns:
        Optional[DNSResponse]: A parsed version of the response, or None if
        the response wasn't for the original query (i.e. had the wrong ID).
    """

    # step 1: unpack header and check that query ID is correct

    header_format = "!HHHHHH"
    header_size = struct.calcsize(header_format)
    header_fields = struct.unpack(header_format, response[:header_size])


    query_id, flags, qdcount, ancount, nscount, arcount = header_fields

    if query_id != expected_query_id:
        return None  # ID mismatch, potentially ignoring the response


    # step 2: parse the Question section
    question_start = header_size
    query_name, question_end = decode_dns_name(response, question_start)
    qtype, qclass = struct.unpack("!HH", response[question_end:question_end+4])

    dns_response = DNSResponse(query_name, DNSRecordType(qtype))


    # step 3: Parse the Answer, Authority, and Additional sections
    current_position = question_end + 4  #based on the question parsing

    # Function to parse a specific section and append records to the DNSResponse
    def parse_section(response, start, count, append_to):
        current_pos = start
        for _ in range(count):
            record, next_pos = parse_record(response, current_pos)
            append_to.append(record)
            current_pos = next_pos
        return current_pos

    # Parse Answer Section
    current_position = parse_section(response, current_position, ancount, dns_response.answers)

    # Parse Authority Section
    current_position = parse_section(response, current_position, nscount, dns_response.authorities)

    # Parse Additional Section
    current_position = parse_section(response, current_position, arcount, dns_response.additional)

    return dns_response


def query_servers(query: bytes, servers: list[str]) -> Optional[bytes]:
    """
    Sends the given query to the servers, one at a time, stopping once it gets
    a response from one of them. Returns None if all of the servers timeout.

    Args:
        query (bytes): The message to send to the servers.
        servers (list[str]): A list of IP addresses for the servers.

    Returns:
        Optional[bytes]: The data received from one of the servers, or None if
        none of the servers responded.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)   # socket should timeout after 2 seconds

    for server in servers:
        sock.sendto(query, (server, 53))
        try:
            response = sock.recv(4096)

        except socket.timeout:
            print("Time out!")
        
        else:
            return response
            
    return None

def determine_target_type(is_mx: bool) -> DNSRecordType:
    """
    Determines the target DNS record type (A for address or MX for mail exchange)
    based on the query's requirement.

    Args:
        is_mx (bool): Flag indicating if the query is for an MX record.

    Returns:
        DNSRecordType: The DNS record type that should be queried.
    """
    return DNSRecordType.MX if is_mx else DNSRecordType.A

def find_direct_answer(response_records: DNSResponse, target: str, target_type: DNSRecordType) -> Optional[str]:
    """
    Searches for a direct answer for the given target and record type within the DNS response.

    Args:
        response_records (DNSResponse): The DNS response containing potential answers.
        target (str): The target hostname for which an answer is sought.
        target_type (DNSRecordType): The type of DNS record sought (A or MX).

    Returns:
        Optional[str]: The direct answer's value if found, or None if no direct answer is available.
    """
    direct_answer = response_records.get_answer(target, target_type)
    if direct_answer:
        return direct_answer.value_string()
    return None

def handle_cname_record(response_records: DNSResponse, target: str) -> tuple[str, bool]:
    """
    Checks if there is a CNAME record for the target and returns the canonical name if found.

    Args:
        response_records (DNSResponse): The DNS response to check for a CNAME record.
        target (str): The target hostname for which a CNAME record is sought.

    Returns:
        tuple[str, bool]: A tuple containing the canonical name (if a CNAME record is found)
        and a boolean indicating whether a CNAME record was found.
    """
    cname_record = response_records.get_answer(target, DNSRecordType.CNAME)
    if cname_record:
        return str(cname_record.value), True
    return target, False

def resolve_query(hostname: str, is_mx: bool, response_records: DNSResponse, cname: bool) -> Optional[str]:
    """
    Resolves the given hostname by analyzing the DNS response. It handles cases where a CNAME
    record is found, or where NS server IPs are needed for resolution.

    Args:
        hostname (str): The hostname to resolve.
        is_mx (bool): Flag indicating if the query is for an MX record.
        response_records (DNSResponse): The DNS response containing potential answers, authority, and additional records.
        cname (bool): Flag indicating if a CNAME record was encountered during resolution.

    Returns:
        Optional[str]: The resolved IP address or mail server, or None if the query could not be resolved.
    """

    if cname:
        return resolve(hostname, get_root_servers(), is_mx)
    
    # Extract NS records from the AUTHORITY section and maintain their order.
    ns_servers = [record.value for record in response_records.authorities if record.type == DNSRecordType.NS]

    # find IP addresses for these NS servers in the ADDITIONAL section while SAVING order.
    ns_server_ips_ordered = []
    for ns_server in ns_servers:
        for add_record in response_records.additional:
            if add_record.name == ns_server and add_record.type == DNSRecordType.A:
                ns_server_ips_ordered.append(add_record.value_string())
                break  # Move to the next NS server once an IP is found.

    # Use ordered NS server IPs for resolution (if posible).
    if ns_server_ips_ordered:
        return resolve(hostname, ns_server_ips_ordered, is_mx)

    # Attempt to resolve at least one NS server to an IP if no IPs were found in the ADDITIONAL section.
    if ns_servers:
        for ns_server in ns_servers:
            ##CORRECT FORMAT
            if isinstance(ns_server, str):
                ns_server_ip = resolve(ns_server, get_root_servers(), False)
                if ns_server_ip:
                    # Resolve the original hostname using the resolved NS server IP.
                    return resolve(hostname, [ns_server_ip], is_mx)

    # If no NS server IPs could be resolved, fallback to using root servers.
    return resolve(hostname, get_root_servers(), is_mx)



def locate_answer(hostname: str, is_mx: bool, response_records: DNSResponse) -> Optional[str]:
    """
    Uses the given response to resolve the query (with the given id) for the given hostname.

    Args:
        hostname (string): The name of the host to resolve.
        is_mx (boolean): True if requesting the MX record result, False if
          requesting the A record.
        response_record (DNSResponse): The parsed response to be examined.

    Returns:
        Optional[str]: A string representation of an IP address (e.g. "192.168.0.1") or
          mail server (e.g. "mail.google.com"). If the request could not be
          resolved, None will be returned.
    """
    logging.info("Looking for answer in response.")
    logging.debug(response_records)

    # TLD validation
    extracted = tldextract.extract(hostname)
    if not extracted.suffix:
        logging.error(f"Error: The hostname '{hostname}' has an invalid TLD.")
        return None

    target_type = determine_target_type(is_mx)
    target,cname = handle_cname_record(response_records, hostname)
    direct_answer = find_direct_answer(response_records, target, target_type)
    if direct_answer:
        return direct_answer
    
    if not response_records.authorities and not response_records.answers:
        logging.error("No authoritative or direct answers, indicating a possible resolution issue.")
        return None
    
    if any(record.type == DNSRecordType.SOA for record in response_records.authorities) and not response_records.answers:
        logging.error(f"SOA record found without corresponding A or MX records for {hostname}, indicating non-existence.")
        print(f"Error: The hostname '{hostname}' does not have an A or MX record.")
        return None
    
    
    return resolve_query(target, is_mx, response_records,cname)
    
    

def resolve(hostname: str, servers: list[str], is_mx: bool=False) -> Optional[str]:
    """
    Returns a string with the IP address (for an A record) or name of mail
    server associated with the given hostname.

    Args:
        hostname (string): The name of the host to resolve.
        servers (list[str]): List of IP addresses for DNS servers to query
        is_mx (boolean): True if requesting the MX record result, False if
          requesting the A record.

    Returns:
        Optional[string]: A string representation of an IP address (e.g. "192.168.0.1") or
          mail server (e.g. "mail.google.com"). If the request could not be
          resolved, None will be returned.
    """
    logging.info(f"Resolving {hostname} (type={'A' if not is_mx else 'MX'}) using the following servers: {servers}")

    # Step 1: Use the construct_query function to create a query of the
    # appropriate type, using a randomly generated ID between 0 and 65535 (i.e. 2^16-1)
    id = random.randrange(0,65535)
    query = construct_query(id,hostname, determine_target_type(is_mx))

    # Step 2: Send the query to the servers
    data = query_servers(query,servers)
    if data is None:
        # Handle the case where no response is received.
        logging.error("No response received from any server.")
        return None

    # Step 3: Parse the response
    dns_response = parse_response(data,id)
    if dns_response is None:
        # Handle the case where parsing fails or the response is for a different query.
        logging.error("Failed to parse response or response ID mismatch.")
        return None

    # Step 4: Use the locate_function to determine the answer to the query
    answerrr = locate_answer(hostname,is_mx,dns_response)

    return answerrr 


def main() -> None:
    """ Parses command line arguments and calls resolver based on the
    specified type of query, displaying the result to the user. """

    # parse the command line arguments
    parser = ArgumentParser(prog="resolver.py",
                            description="An iterative DNS resolver for A and MX queries.")
    parser.add_argument('name', help="The hostname to resolve.")
    parser.add_argument('-m', '--mx', action='store_true',
                        help="Perform an MX instead of an A query.")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="Print detailed program output to screen.")
    args = parser.parse_args()


    setup_logging(args.verbose)


    roots = get_root_servers()
    answer = resolve(args.name, roots, is_mx=args.mx)

    if answer is not None:
        if args.mx:
            print(f"Mail Server for {args.name}: {answer}")
        else:
            print(f"IP address for {args.name}: {answer}")

    else:
        print("ERROR: Could not resolve request.")


def setup_logging(verbose_output: bool) -> None:
    """ Sets up logging to a file (output.log) as well as to the screen.

    Args:
        verbose_output (bool): True if logger should print DEBUG level
        messages to screen, False to print WARNING level and above only.
    """
    log = logging.getLogger()

    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s: %(message)s')

    # set up logging to the output.log file
    fh = logging.FileHandler('output.log', mode='w', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    log.addHandler(fh)

    # set up logging to the screen, based on the verbosity level set by user
    ch = logging.StreamHandler()
    if verbose_output:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.WARNING)
    log.addHandler(ch)


if __name__ == "__main__":
    main()
