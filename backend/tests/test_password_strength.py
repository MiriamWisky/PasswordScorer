import pytest
from app import extract_features, get_prediction_and_crack_time, create_smart_variation

def test_extract_features():
    """Test password feature extraction"""
    # Test weak password (digits only)
    features = extract_features("123")
    assert features[0][0] == 3  # length
    assert features[0][1] == 1  # char_variety (only digits)
    
    # Test strong password
    features = extract_features("MyStr0ng!Pass")
    assert features[0][0] == 13  # length
    assert features[0][1] == 4   # char_variety (upper+lower+digit+special)

def test_password_strength_prediction():
    """Test password strength prediction"""
    try:
        # Test weak password
        strength, time = get_prediction_and_crack_time("123")
        assert strength in [0, 1, 2]
        assert isinstance(time, str)
        
        # Test strong password
        strength, time = get_prediction_and_crack_time("MyVeryStr0ng!Password123")
        assert strength in [0, 1, 2]
        assert isinstance(time, str)
    except FileNotFoundError:
        # Model not loaded in test environment
        pytest.skip("ML Model not available in test environment")

def test_smart_variation():
    """Test smart password variation generation"""
    password_list = ["password123", "mypassword", "testpass"]
    
    # Test with password list
    variation = create_smart_variation(password_list)
    assert isinstance(variation, str)
    assert len(variation) >= 6
    
    # Test with empty list
    variation = create_smart_variation([])
    assert isinstance(variation, str)
    assert len(variation) >= 8