import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
import pickle

def create_mock_model(filename="backend/password_model.pkl"):
    print("Generating improved ML model...")
    np.random.seed(42)
    
    # Create more realistic training data
    passwords = [
        # Weak passwords (0) - digits only, short, no variety
        [3, 0, 1.5], [4, 0, 2], [5, 0, 2.5], [6, 0, 3], [7, 0, 3.5], [8, 0, 4], [9, 0, 4.5],
        [6, 1, 9], [7, 1, 10], [8, 1, 11], [9, 1, 12],  # Only one char type
        
        # Medium passwords (1) - some variety, decent length
        [8, 2, 14], [9, 2, 15], [10, 2, 16], [11, 2, 17],
        [8, 3, 19], [9, 3, 20], [10, 3, 21],
        
        # Strong passwords (2) - good length + variety + special chars
        [12, 4, 29], [13, 4, 32], [14, 4, 35], [15, 4, 38],
        [10, 4, 25], [11, 4, 28], [16, 4, 41], [20, 4, 53]
    ]
    
    X = np.array(passwords)
    y = np.array([0]*11 + [1]*7 + [2]*8)
    
    model = LogisticRegression(max_iter=1000)
    model.fit(X, y)

    with open(filename, 'wb') as file:
        pickle.dump(model, file)

    print(f"Mock model saved successfully as {filename}.")

if __name__ == '__main__':
    create_mock_model(filename="password_model.pkl")