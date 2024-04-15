"""
Module: test_resolve

PyTest unit tests for the resolve function
"""
import pytest
from unittest.mock import patch, Mock, call
import socket

import resolver

@patch('resolver.randrange')
@patch('resolver.construct_query')
@patch('resolver.query_servers')
@patch('resolver.parse_response')
@patch('resolver.locate_answer')
def test_resolve(mock_locate_answer, mock_parse_response, mock_query_servers,
                   mock_construct_query, mock_randrange):

    # test resolve of A record
    mock_locate_answer.return_value = "4.5.6.7"
    mock_parse_response.return_value = "woohoo"
    mock_query_servers.return_value = b'response'
    mock_construct_query.return_value = b'hello'
    mock_randrange.return_value = 731

    answer = resolver.resolve("www.whateva.org", ['7.7.7.7','8.8.8.8'], False)
    assert answer == "4.5.6.7"
    mock_randrange.called_once_with(65536)
    mock_construct_query.called_once_with(731, "www.whateva.org", resolver.DNSRecordType.A)
    mock_query_servers.called_once_with(b'hello', ['7.7.7.7', '8.8.8.8'])
    mock_parse_response.called_once_with(b'response', 731)
    mock_locate_answer.called_once_with("www.whateva.org", False, "woohoo")

    mock_locate_answer.reset_mock()
    mock_parse_response.reset_mock()
    mock_query_servers.reset_mock()
    mock_construct_query.reset_mock()
    mock_randrange.reset_mock()

    # test resolve of MX record
    mock_locate_answer.return_value = "coolmail.whateva.org"

    answer = resolver.resolve("www.whateva.org", ['7.7.7.7','8.8.8.8'], True)
    assert answer == "coolmail.whateva.org"
    mock_construct_query.called_once_with(731, "www.whateva.org",
                                          resolver.DNSRecordType.MX)
    mock_locate_answer.called_once_with("www.whateva.org", True, "woohoo")

if __name__ == "__main__":
    pytest.main(['test_resolve.py', '-v'])
