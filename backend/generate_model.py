import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
import pickle

def create_mock_model(filename="backend/password_model.pkl"):
    print("Generating mock ML model...")
    np.random.seed(42)
    X = np.random.rand(100, 3) * 10
    y = np.where(X.sum(axis=1) > 15, 2, np.where(X.sum(axis=1) > 10, 1, 0))

    model = LogisticRegression(max_iter=1000)
    model.fit(X, y)

    with open(filename, 'wb') as file:
        pickle.dump(model, file)

    print(f"Mock model saved successfully as {filename}.")

if __name__ == '__main__':
    create_mock_model(filename="backend/password_model.pkl")