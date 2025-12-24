import pytest
import json
from unittest.mock import patch, MagicMock
from app import app, hash_password
import jwt
from datetime import datetime, timedelta

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    with app.test_client() as client:
        yield client

@pytest.fixture
def mock_db():
    """Mock database connection"""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
    return mock_conn, mock_cursor

@patch('app.get_db_connection')
def test_register_user(mock_get_db, client, mock_db):
    """Test user registration"""
    mock_conn, mock_cursor = mock_db
    mock_get_db.return_value = mock_conn
    mock_cursor.fetchone.return_value = [1]
    
    response = client.post('/register', 
                          data=json.dumps({'username': 'testuser', 'password': 'testpass123'}),
                          content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert 'token' in data

@patch('app.get_db_connection')
def test_login_user(mock_get_db, client, mock_db):
    """Test user login"""
    mock_conn, mock_cursor = mock_db
    mock_get_db.return_value = mock_conn
    
    # Mock user exists with bcrypt password hash
    password_hash = hash_password('testpass123')
    mock_cursor.fetchone.return_value = [1, password_hash]
    
    response = client.post('/login', 
                          data=json.dumps({'username': 'testuser2', 'password': 'testpass123'}),
                          content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert 'token' in data

@patch('app.get_db_connection')
def test_password_scoring(mock_get_db, client, mock_db):
    """Test password scoring functionality"""
    mock_conn, mock_cursor = mock_db
    mock_get_db.return_value = mock_conn
    
    # Generate JWT token for authentication
    from app import generate_token
    token = generate_token(1)
    
    # Test password scoring
    response = client.post('/score', 
                          data=json.dumps({'password': 'weakpass', 'save_to_db': False}),
                          content_type='application/json',
                          headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'strength' in data
    assert 'crack_time' in data

@patch('app.get_db_connection')
def test_password_history(mock_get_db, client, mock_db):
    """Test password history retrieval"""
    mock_conn, mock_cursor = mock_db
    mock_get_db.return_value = mock_conn
    
    # Simulate logged in user
    with client.session_transaction() as sess:
        sess['user_id'] = 1
    
    # Mock history data
    from datetime import datetime
    mock_cursor.fetchall.return_value = [
        ('testpassword123', 1, datetime.now())
    ]
    
    # Get history
    response = client.get('/history')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)

@patch('app.get_db_connection')
def test_password_recommendation(mock_get_db, client, mock_db):
    """Test password recommendation"""
    mock_conn, mock_cursor = mock_db
    mock_get_db.return_value = mock_conn
    
    # Simulate logged in user
    with client.session_transaction() as sess:
        sess['user_id'] = 1
    
    # Mock password history for recommendations
    mock_cursor.fetchall.return_value = [
        ('password123',), ('mypassword',)
    ]
    
    # Get recommendation
    response = client.get('/recommend')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'password' in data
    assert 'strength' in data

def test_unauthorized_access(client):
    """Test that endpoints require authentication"""
    response = client.get('/history')
    assert response.status_code == 401
    
    response = client.post('/score', 
                          data=json.dumps({'password': 'test'}),
                          content_type='application/json')
    assert response.status_code == 401

def test_metrics_endpoint(client):
    """Test Prometheus metrics endpoint"""
    response = client.get('/metrics')
    assert response.status_code == 200
    assert 'password_requests_total' in response.data.decode()