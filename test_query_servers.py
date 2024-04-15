"""
Module: test_query_servers

PyTest unit tests for the query_servers function
"""
import pytest
from unittest.mock import patch, Mock, call
import socket

import resolver

@patch('socket.socket')
def test_first_responds(mock_socket):
    """ Test when first server responds. """
    instance = mock_socket()
    instance.return_value = Mock()
    instance.recv.return_value = b'result';
    result = resolver.query_servers(b"input",['1.2.3.4'])

    mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_DGRAM)
    instance.settimeout.assert_called_once_with(2)
    instance.recv.assert_called_once_with(4096)
    assert result == b'result'

@patch('socket.socket')
def test_second_responds(mock_socket):
    """ Test that query_servers handles a timeout correctly. """
    instance = mock_socket()
    instance.return_value = Mock()
    instance.recv.side_effect = [socket.timeout, b'result'];
    mock_socket.reset_mock()

    result = resolver.query_servers(b"input",['1.2.3.4', '5.6.7.8'])
    mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
    instance.settimeout.assert_called_once_with(2)
    assert instance.sendto.call_count == 2
    expected_calls = [call(b"input", ('1.2.3.4', 53)), call(b"input", ('5.6.7.8', 53))]
    assert instance.sendto.call_args_list == expected_calls
    assert result == b'result'

@patch('socket.socket')
def test_none_respond(mock_socket):
    """ Test that query_servers returns None when all servers timeout.  """
    instance = mock_socket()
    instance.return_value = Mock()
    instance.recv.side_effect = socket.timeout
    mock_socket.reset_mock()

    result = resolver.query_servers(b"input",['1.2.3.4', '5.6.7.8'])
    assert instance.sendto.call_count == 2
    expected_calls = [call(b"input", ('1.2.3.4', 53)), call(b"input", ('5.6.7.8', 53))]
    assert instance.sendto.call_args_list == expected_calls

    assert result is None

if __name__ == "__main__":
    pytest.main(['test_query_servers.py', '-v'])
