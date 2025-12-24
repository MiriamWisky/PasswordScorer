import pytest
import json
from unittest.mock import patch, MagicMock
from app import app, create_table_if_not_exists, generate_token

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            create_table_if_not_exists()
        yield client

@pytest.fixture
def auth_token():
    """Create a test user and return auth token"""
    return generate_token(1)  # Using user_id=1 for tests

class TestPoemGeneration:
    
    def test_poem_generation_no_token(self, client):
        """Test poem generation without authentication token"""
        response = client.post('/password-poem', 
                             json={'password': 'TestPass123!'})
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data

    def test_poem_generation_no_password(self, client, auth_token):
        """Test poem generation without password"""
        response = client.post('/password-poem',
                             headers={'Authorization': f'Bearer {auth_token}'},
                             json={})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'נדרשת סיסמה ליצירת שיר'

    def test_poem_generation_short_password(self, client, auth_token):
        """Test poem generation with too short password"""
        response = client.post('/password-poem',
                             headers={'Authorization': f'Bearer {auth_token}'},
                             json={'password': '123'})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'הסיסמה קצרה מדי ליצירת שיר'

    @patch('app.GEMINI_API_KEY', '')
    def test_poem_generation_no_api_key(self, client, auth_token):
        """Test poem generation without Gemini API key"""
        response = client.post('/password-poem',
                             headers={'Authorization': f'Bearer {auth_token}'},
                             json={'password': 'TestPass123!'})
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'צריך מפתח Gemini API' in data['poem']

    @patch('requests.post')
    @patch('app.GEMINI_API_KEY', 'test-api-key')
    def test_poem_generation_success(self, mock_post, client, auth_token):
        """Test successful poem generation"""
        # Mock successful Gemini API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'candidates': [{
                'content': {
                    'parts': [{
                        'text': '🎵 שיר הסיסמה שלי 🎵\nסיסמה חזקה ומוגנת\nעם מספרים ואותיות\nתשמור עליי תמיד! 🔐'
                    }]
                }
            }]
        }
        mock_post.return_value = mock_response

        response = client.post('/password-poem',
                             headers={'Authorization': f'Bearer {auth_token}'},
                             json={'password': 'TestPass123!'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'poem' in data
        assert '🎵 שיר הסיסמה שלי 🎵' in data['poem']
        assert 'message' in data

    @patch('requests.post')
    @patch('app.GEMINI_API_KEY', 'test-api-key')
    def test_poem_generation_api_error(self, mock_post, client, auth_token):
        """Test poem generation with API error"""
        # Mock failed Gemini API response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        response = client.post('/password-poem',
                             headers={'Authorization': f'Bearer {auth_token}'},
                             json={'password': 'TestPass123!'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'poem' in data
        assert 'שגיאה ביצירת השיר' in data['poem']

    @patch('requests.post')
    @patch('app.GEMINI_API_KEY', 'test-api-key')
    def test_poem_generation_timeout(self, mock_post, client, auth_token):
        """Test poem generation with timeout"""
        # Mock timeout exception
        mock_post.side_effect = Exception("Timeout")

        response = client.post('/password-poem',
                             headers={'Authorization': f'Bearer {auth_token}'},
                             json={'password': 'TestPass123!'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'poem' in data
        assert 'לא הצלחתי ליצור שיר היום' in data['poem']

    def test_poem_hints_extraction(self, client, auth_token):
        """Test that poem generation uses only safe hints"""
        with patch('requests.post') as mock_post, \
             patch('app.GEMINI_API_KEY', 'test-api-key'):
            
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'candidates': [{
                    'content': {
                        'parts': [{
                            'text': '🎵 שיר בדיקה 🎵'
                        }]
                    }
                }]
            }
            mock_post.return_value = mock_response

            response = client.post('/password-poem',
                                 headers={'Authorization': f'Bearer {auth_token}'},
                                 json={'password': 'MySecret123!'})
            
            # Check that the actual password was not sent to API
            call_args = mock_post.call_args
            request_data = call_args[1]['json']
            prompt = request_data['contents'][0]['parts'][0]['text']
            
            # Password should not appear in prompt
            assert 'MySecret123!' not in prompt
            # But hints should be there
            assert 'אורך: 12' in prompt
            assert 'יש מספרים' in prompt
            assert 'יש אותיות גדולות' in prompt