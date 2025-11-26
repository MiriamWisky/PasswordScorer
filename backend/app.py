import os
import pickle
from flask import Flask, request, jsonify, session
import numpy as np
import psycopg2
from dotenv import load_dotenv
import hashlib
import random 
from collections import defaultdict
import string
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
import time
import uuid

# --- 1. Initialization and Model Loading ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# Prometheus metrics
REQUEST_COUNT = Counter('password_requests_total', 'Total password requests', ['endpoint', 'method'])
REQUEST_LATENCY = Histogram('password_request_duration_seconds', 'Request latency')
PASSWORD_STRENGTH = Counter('password_strength_total', 'Password strength distribution', ['strength'])
DB_OPERATIONS = Counter('database_operations_total', 'Database operations', ['operation', 'status'])

def extract_features(password):
    length = len(password)
    has_upper = 1 if any(c.isupper() for c in password) else 0
    has_special = 1 if any(not c.isalnum() for c in password) else 0

    complexity_score = length + (has_upper * 5) + (has_special * 10)

    return np.array([length, has_upper, complexity_score]).reshape(1, -1)

# Load the pre-trained model once when the app starts
MODEL = None
try:
    with open('password_model.pkl', 'rb') as file:
        MODEL = pickle.load(file)
    print("ML Model loaded successfully.")
except FileNotFoundError:
    print("ERROR: password_model.pkl not found. Please run generate_model.py!")


def get_prediction_and_crack_time(password):
    """Performs the ML prediction and maps it to a crack time string."""
    if not MODEL:
        raise FileNotFoundError("ML Model not loaded.")

    # 1. חיזוי
    features = extract_features(password)
    prediction = MODEL.predict(features)[0]

    # 2. מיפוי התוצאה
    strength_map = {
        0: {"level": "חלשה", "time": "פחות משעה"},
        1: {"level": "בינונית", "time": "ימים עד שבועות"},
        2: {"level": "חזקה", "time": "שנים"}
    }
    result = strength_map.get(prediction, {"level": "לא ידוע", "time": "N/A"})

    return int(prediction), result["time"]


# --- 2. Database Connection Logic ---
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host="db",
            database=os.environ.get("POSTGRES_DB", "password_db"),
            user=os.environ.get("POSTGRES_USER", "devops_user"),
            password=os.environ.get("POSTGRES_PASSWORD", "supersecretpassword")
        )
        return conn
    except Exception as e:
        print(f"DB CONNECTION ERROR: {e}")
        return None

def create_table_if_not_exists():
    conn = get_db_connection()
    if conn:
        with conn.cursor() as cur:
            # יצירת טבלת משתמשים
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            # יצירת טבלת סיסמאות (אם לא קיימת)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_scores (
                    id SERIAL PRIMARY KEY,
                    password_hash VARCHAR(255) NOT NULL,
                    plain_password VARCHAR(255) NOT NULL,
                    score INTEGER NOT NULL,
                    prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            # הוספת עמודת user_id אם לא קיימת
            try:
                cur.execute("""
                    ALTER TABLE password_scores 
                    ADD COLUMN user_id INTEGER REFERENCES users(id);
                """)
                print("Added user_id column to password_scores table")
            except Exception as e:
                if "already exists" in str(e) or "duplicate column" in str(e):
                    print("user_id column already exists")
                else:
                    print(f"Error adding user_id column: {e}")
            
            # יצירת משתמש ברירת מחדל לרשומות ישנות
            try:
                cur.execute("SELECT id FROM users WHERE username = 'default_user'")
                if not cur.fetchone():
                    cur.execute("""
                        INSERT INTO users (username, password_hash) 
                        VALUES ('default_user', 'default_hash')
                    """)
                    print("Created default user")
                    
                # עדכון רשומות ישנות למשתמש ברירת מחדל
                cur.execute("SELECT id FROM users WHERE username = 'default_user'")
                default_user_id = cur.fetchone()[0]
                
                cur.execute("""
                    UPDATE password_scores 
                    SET user_id = %s 
                    WHERE user_id IS NULL
                """, (default_user_id,))
                print("Updated old records with default user")
            except Exception as e:
                print(f"Error handling default user: {e}")
                    
        conn.commit()
        conn.close()

create_table_if_not_exists()

def get_user_id():
    """Get user ID from session"""
    return session.get('user_id')

def is_logged_in():
    """Check if user is logged in"""
    return 'user_id' in session

def generate_strong_password(length=12):
    """Generates a cryptographically strong, random password."""

    # הבטחת לפחות תו אחד מכל קטגוריה
    characters = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice(string.punctuation)
    ]

    # השלמת הסיסמה עד לאורך הרצוי
    all_chars = string.ascii_letters + string.digits + string.punctuation
    characters += [random.choice(all_chars) for _ in range(length - len(characters))]

    # ערבוב התווים
    random.shuffle(characters)
    return "".join(characters)


MARKOV_MODEL = None # מודל גלובלי למרכוב צ'יין

def build_markov_model(password_list, order=1):  # הקטנת ה-order ל-1 לדמיון טוב יותר
    """Builds a Markov Chain model from a list of passwords."""
    model = defaultdict(lambda: defaultdict(int))

    # בניית טבלת מעברים
    for password in password_list:
        # הוספת תווים מיוחדים להתחלה וסוף
        processed_pass = "^" * order + password.lower() + "$"  # הפיכה לאותיות קטנות

        for i in range(len(processed_pass) - order):
            prefix = processed_pass[i:i + order]
            suffix = processed_pass[i + order]
            model[prefix][suffix] += 1

    # נורמליזציה (הפיכת ספירות להסתברויות)
    for prefix, suffixes in model.items():
        total = sum(suffixes.values())
        for suffix in suffixes:
            suffixes[suffix] /= total

    return dict(model)

def create_smart_variation(password_list):
    """Create smart variations based on existing passwords."""
    if not password_list:
        return generate_strong_password(8)
    
    # בחירת סיסמה בסיסית אקראית
    base_password = random.choice(password_list).lower()
    
    # אסטרטגיות שונות לוריאציה
    strategies = [
        # הוספת מספרים
        lambda p: p + str(random.randint(1, 999)),
        lambda p: p + str(random.randint(10, 99)),
        lambda p: str(random.randint(1, 99)) + p,
        
        # כפילות חלקיות
        lambda p: p + p[:3] if len(p) >= 3 else p + p,
        lambda p: p[:4] + p[:4] if len(p) >= 4 else p + p,
        
        # שינוי קל באותיות
        lambda p: p.replace('i', 'y') if 'i' in p else p,
        lambda p: p.replace('a', 'e') if 'a' in p else p,
        
        # הוספת תווים מיוחדים
        lambda p: p + random.choice(['!', '@', '#', '$', '%']),
        lambda p: p + random.choice(['123', '456', '789']),
        
        # שילוב של שתי סיסמאות
        lambda p: (p[:len(p)//2] + random.choice(password_list).lower()[:4]) if len(password_list) > 1 else p + '123'
    ]
    
    # בחירת אסטרטגיה אקראית ויישום
    strategy = random.choice(strategies)
    result = strategy(base_password)
    
    # וידוא שהתוצאה לא קצרה מדי
    if len(result) < 6:
        result += str(random.randint(10, 99))
    
    # הגבלת אורך מקסימלי
    if len(result) > 20:
        result = result[:20]
    
    return result


def generate_password_from_markov(model, min_length=8, max_length=15, order=2):
    """Generates a password using the Markov model with better similarity to input."""
    
    attempts = 0
    while attempts < 10:  # מספר ניסיונות מוגבל
        prefix = "^" * order
        password = ""
        
        while len(password) < max_length:
            suffixes = model.get(prefix)
            if not suffixes:
                # אם אין המשך, נסה להתחיל מחדש עם prefix אחר
                available_prefixes = [p for p in model.keys() if not p.startswith("$")]
                if available_prefixes:
                    prefix = random.choice(available_prefixes)
                    continue
                else:
                    break
            
            # בחירת תו על פי הסתברויות
            suffixes_list = list(suffixes.keys())
            probabilities = list(suffixes.values())
            
            next_char = random.choices(suffixes_list, weights=probabilities, k=1)[0]
            
            if next_char == "$":
                break
                
            password += next_char
            prefix = prefix[1:] + next_char
        
        # בדיקה שהסיסמה באורך מתאים
        if min_length <= len(password) <= max_length:
            return password
            
        attempts += 1
    
    # אם לא הצלחנו ליצור סיסמה טובה, נחזיר סיסמה אקראית
    return generate_strong_password(8)


# --- 3. API Endpoint ---
# בקובץ backend/app.py
# ... (שאר הקוד וה-Imports)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"error": "נדרש שם משתמש וסיסמה"}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "שגיאת חיבור למסד נתונים"}), 500
    
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            
            if user and hashlib.sha256(password.encode()).hexdigest() == user[1]:
                session['user_id'] = user[0]
                return jsonify({"success": True, "message": "התחברת בהצלחה"})
            else:
                return jsonify({"error": "שם משתמש או סיסמה שגויים"}), 401
    finally:
        conn.close()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"error": "נדרש שם משתמש וסיסמה"}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "שגיאת חיבור למסד נתונים"}), 500
    
    try:
        with conn.cursor() as cur:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id", 
                       (username, password_hash))
            user_id = cur.fetchone()[0]
            session['user_id'] = user_id
            conn.commit()
            return jsonify({"success": True, "message": "נרשמת בהצלחה"})
    except Exception as e:
        if "duplicate key" in str(e):
            return jsonify({"error": "שם המשתמש כבר קיים"}), 409
        return jsonify({"error": "שגיאה ביצירת המשתמש"}), 500
    finally:
        conn.close()

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "התנתקת בהצלחה"})

@app.route('/score', methods=['POST'])
def score_password():
    """Endpoint לבדיקה ושמירה ל-DB (פועל רק אם save_to_db=True)."""
    if not is_logged_in():
        return jsonify({"error": "נדרשת התחברות"}), 401
        
    start_time = time.time()
    REQUEST_COUNT.labels(endpoint='score', method='POST').inc()
    
    data = request.get_json()
    password = data.get('password', '')
    save_to_db = data.get('save_to_db', False)
    
    if not password:
        return jsonify({"strength": -1, "crack_time": "נדרשת סיסמה."})

    try:
        # 1. בצע חיזוי וקבלת זמן פיצוח
        prediction, crack_time = get_prediction_and_crack_time(password)

        # 2. שמירה ל-DB (רק אם קיבלנו דגל שמירה)
        if save_to_db:
            conn = get_db_connection()
            if conn:
                with conn.cursor() as cur:
                    user_id = get_user_id()
                    password_hash = hashlib.sha256(password.encode()).hexdigest()
                    cur.execute("""
                        INSERT INTO password_scores (user_id, password_hash, plain_password, score)
                        VALUES (%s, %s, %s, %s);
                    """, (user_id, password_hash, password, prediction))
                conn.commit()
                conn.close()
            
        # 3. החזר תמיד את התוצאה ל-Frontend
        PASSWORD_STRENGTH.labels(strength=str(prediction)).inc()
        REQUEST_LATENCY.observe(time.time() - start_time)
        
        return jsonify({
            "strength": prediction,
            "crack_time": crack_time,
            "clear_input": save_to_db
        })

    except FileNotFoundError as e:
        print(f"File Error: {e}")
        return jsonify({"error": "ML Model not loaded."}), 500
    except Exception as e:
        print(f"General Error: {e}")
        return jsonify({"error": "Internal server error."}), 500
    
# --- 4. New API Endpoint: Get History ---
@app.route('/history', methods=['GET'])
def get_password_history():
    """
    Endpoint for retrieving all saved password scores from the database.
    """
    if not is_logged_in():
        return jsonify({"error": "נדרשת התחברות"}), 401
        
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500
    
    results = []
    try:
        with conn.cursor() as cur:
            user_id = get_user_id()
            cur.execute("""
                SELECT plain_password, score, prediction_time
                FROM password_scores 
                WHERE user_id = %s
                ORDER BY prediction_time DESC
                LIMIT 10;
            """, (user_id,))
            # ה-score (0, 1, 2) הופך לטקסט לצורך הצגה
            strength_map = {0: "חלשה", 1: "בינונית", 2: "חזקה"}
            
            for row in cur.fetchall():
                results.append({
                    "password": row[0],
                    "strength_level": strength_map.get(row[1], "לא ידוע"),
                    "timestamp": row[2].isoformat()
                })
        
        conn.close()
        return jsonify(results)
    
    except Exception as e:
        conn.close()
        print(f"ERROR fetching history: {e}")
        return jsonify({"error": "Failed to retrieve history."}), 500


@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/recommend', methods=['GET'])
def recommend_password():
    """Endpoint המאמן מודל Markoc Chain על סיסמאות קודמות ומציע סיסמה חדשה."""

    # 1. שליפת סיסמאות חלשות שנשמרו מה-DB
    conn = get_db_connection()
    if not conn:
         return jsonify({"error": "DB connection failed for recommendation."}), 500

    # שליפת כל הסיסמאות שנשמרו ללמידה
    with conn.cursor() as cur:
        user_id = get_user_id()
        cur.execute("""
            SELECT plain_password FROM password_scores 
            WHERE user_id = %s
            ORDER BY prediction_time DESC LIMIT 50;
        """, (user_id,))
        password_list = [row[0] for row in cur.fetchall()]
    conn.close()

    if len(password_list) < 2:
         recommended_password = generate_strong_password()
    else:
        recommended_password = create_smart_variation(password_list)

    # 3. בדיקת החוזק של הסיסמה המומלצת
    try:
        prediction, crack_time = get_prediction_and_crack_time(recommended_password)
        return jsonify({
            "password": recommended_password,
            "strength": prediction,
            "crack_time": crack_time
        })
    except Exception as e:
        print(f"Recommendation Error: {e}")
        return jsonify({"error": "Failed to generate recommendation."}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)