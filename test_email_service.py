import pytest
from email_service import send_transfer_email


def test_send_transfer_email_constructs_valid_message(monkeypatch):
    """Test that email is sent with correct content including PIN, filename, and magnet link"""
    sent = {}
    
    def mock_sendmail(self, from_addr, to_addrs, msg):
        sent['from'] = from_addr
        sent['to'] = to_addrs
        sent['msg'] = msg
    
    class MockSMTP:
        def __init__(self, host, port):
            self.host = host
            self.port = port
            
        def starttls(self):
            pass
            
        def login(self, user, password):
            pass
            
        def sendmail(self, from_addr, to_addrs, msg):
            mock_sendmail(self, from_addr, to_addrs, msg)
            
        def quit(self):
            pass
            
        def __enter__(self):
            return self
            
        def __exit__(self, *args):
            pass
    
    monkeypatch.setattr('smtplib.SMTP', MockSMTP)
    
    result = send_transfer_email(
        to_email="recipient@example.com",
        magnet_link="magnet:?xt=urn:btih:abc123",
        pin="123456",
        filename="test.pdf",
        expires_in_seconds=259200
    )
    
    assert result is True
    assert "123456" in sent['msg']
    assert "test.pdf" in sent['msg']
    assert "magnet:?xt=urn:btih:abc123" in sent['msg']
