"""
Test script to verify the Flask application structure.
"""
import os

def test_file_structure():
    """Test that the required files exist."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check if the app directory exists
    app_dir = os.path.join(base_dir, 'app')
    assert os.path.isdir(app_dir), "app directory does not exist"
    print("app directory exists!")
    
    # Check if the required files exist
    required_files = [
        os.path.join(app_dir, '__init__.py'),
        os.path.join(app_dir, 'config.py'),
        os.path.join(app_dir, 'extensions.py'),
        os.path.join(base_dir, 'wsgi.py')
    ]
    
    for file_path in required_files:
        assert os.path.isfile(file_path), f"{file_path} does not exist"
        assert os.path.getsize(file_path) > 0, f"{file_path} is empty"
        print(f"{os.path.basename(file_path)} exists and has content!")
    
    return True

if __name__ == '__main__':
    test_file_structure()
    print("All tests passed! The Flask application structure is set up correctly.")
