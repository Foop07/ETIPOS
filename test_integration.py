import pytest
import subprocess
import time
import requests
import os
import signal

def test_both_servers_start():
    """Test that both FastAPI and Bun tracker servers start correctly"""
    # Set environment variables for testing
    env = os.environ.copy()
    env['P2P_EXPIRY_SECONDS'] = '60'
    env['TRACKER_PORT'] = '8003'  # Use different port for testing
    
    # Start run.py as subprocess
    process = subprocess.Popen(
        ['python', 'run.py'],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    try:
        # Wait for servers to start (max 30 seconds)
        max_wait = 30
        started = False
        
        for i in range(max_wait):
            time.sleep(1)
            
            # Check FastAPI
            try:
                fastapi_resp = requests.get('http://localhost:5000/health', timeout=2)
                fastapi_ok = fastapi_resp.status_code == 200
            except:
                fastapi_ok = False
            
            # Check Bun tracker
            try:
                tracker_resp = requests.get('http://localhost:8003/stats', timeout=2)
                tracker_ok = tracker_resp.status_code == 200
            except:
                tracker_ok = False
            
            if fastapi_ok and tracker_ok:
                started = True
                break
        
        assert started, "Both servers did not start within timeout"
        
        # Verify FastAPI health endpoint
        fastapi_resp = requests.get('http://localhost:5000/health')
        assert fastapi_resp.status_code == 200
        data = fastapi_resp.json()
        assert 'status' in data
        
        # Verify Bun tracker stats endpoint
        tracker_resp = requests.get('http://localhost:8003/stats')
        assert tracker_resp.status_code == 200
        tracker_data = tracker_resp.json()
        assert 'torrents' in tracker_data
        
    finally:
        # Cleanup: kill the process
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def test_p2p_endpoints_work():
    """Test that P2P endpoints are accessible"""
    # This test assumes the server is already running
    # Just verify the endpoints exist
    
    # Test health endpoint includes vault info
    resp = requests.get('http://localhost:5000/health')
    assert resp.status_code == 200
    data = resp.json()
    assert 'vault_active_transfers' in data


def test_environment_variables_loaded():
    """Test that environment variables are properly loaded"""
    # Check if SMTP settings can be read (they'll be None if not set)
    from email_service import SMTP_HOST, SMTP_PORT
    
    assert SMTP_HOST is not None
    assert SMTP_PORT is not None