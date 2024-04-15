"""
Module: test_resolver

PyTest unit test for the parsing phase of Project 3 (DNS resolver).
"""
import pytest
from unittest.mock import patch, Mock, call

import resolver
from helpers import *

@pytest.fixture
def synthetic_response():
    with open('test/synthetic_response.bin', 'rb') as bin_file:
        response = bin_file.read()

    return response

@pytest.fixture
def parsed_synthetic_response():
    parsed_response = DNSResponse("www.example.com", DNSRecordType.A)
    parsed_response.answers.append(DNSRecord("www.example.com",
                                             DNSRecordType.A,
                                             [1,2,3,4]))
    parsed_response.answers.append(DNSRecord("bad.example.com",
                                             DNSRecordType.CNAME,
                                             "good.example.com"))
    parsed_response.authorities.append(DNSRecord("example.com",
                                                 DNSRecordType.NS,
                                                 "ns1.example.com"))
    parsed_response.authorities.append(DNSRecord("example.com",
                                                 DNSRecordType.NS,
                                                 "ns2.example.com"))
    parsed_response.authorities.append(DNSRecord("example.com",
                                                 DNSRecordType.SOA,
                                                 "master.example.com"))
    parsed_response.additional.append(DNSRecord("example.com",
                                                 DNSRecordType.MX,
                                                 "mail.example.com"))
    parsed_response.additional.append(DNSRecord("www.example.com",
                                                 DNSRecordType.AAAA,
                                                 list(range(1,17))))
    return parsed_response

def test_parse_A_record(synthetic_response, parsed_synthetic_response):
    parsed_record, next_index = resolver.parse_record(synthetic_response, 33)
    assert parsed_record == parsed_synthetic_response.answers[0]
    assert next_index == 64

def test_parse_CNAME_record(synthetic_response, parsed_synthetic_response):
    parsed_record, next_index = resolver.parse_record(synthetic_response, 64)
    assert parsed_record == parsed_synthetic_response.answers[1]
    assert next_index == 109

def test_parse_NS_record(synthetic_response, parsed_synthetic_response):
    parsed_record, next_index = resolver.parse_record(synthetic_response, 109)
    assert parsed_record == parsed_synthetic_response.authorities[0]
    assert next_index == 149

def test_parse_SOA_record(synthetic_response, parsed_synthetic_response):
    parsed_record, next_index = resolver.parse_record(synthetic_response, 189)
    assert parsed_record == parsed_synthetic_response.authorities[2]
    assert next_index == 263

def test_parse_MX_record(synthetic_response, parsed_synthetic_response):
    parsed_record, next_index = resolver.parse_record(synthetic_response, 263)
    assert parsed_record == parsed_synthetic_response.additional[0]
    assert next_index == 306

def test_parse_AAAA_record(synthetic_response, parsed_synthetic_response):
    parsed_record, next_index = resolver.parse_record(synthetic_response, 306)
    assert parsed_record == parsed_synthetic_response.additional[1]
    assert next_index == 349

def test_parse_response_result(synthetic_response, parsed_synthetic_response):
    actual_result = resolver.parse_response(synthetic_response, 25)
    assert actual_result == parsed_synthetic_response

@patch('resolver.parse_record')
def test_parse_response_calls_parse_record(mock_parse_record, synthetic_response):
    """ Checks that parse_response actually uses parse_record to do its work.  """
    mock_parse_record.side_effect = lambda response, index: (index, index+1)
    resolver.parse_response(synthetic_response, 25)
    assert mock_parse_record.call_count == 7


if __name__ == "__main__":
    pytest.main(['test_parsing.py', '-v'])
