import os
import pickle
from flask import Flask, request, jsonify
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
import jwt
import bcrypt
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import google.generativeai as genai

# --- 1. Initialization and Model Loading ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'jwt-secret-key-change-in-production')
JWT_EXPIRATION_HOURS = 24

# Gemini AI Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Prometheus metrics
REQUEST_COUNT = Counter('password_requests_total', 'Total password requests', ['endpoint', 'method'])
REQUEST_LATENCY = Histogram('password_request_duration_seconds', 'Request latency')
PASSWORD_STRENGTH = Counter('password_strength_total', 'Password strength distribution', ['strength'])
DB_OPERATIONS = Counter('database_operations_total', 'Database operations', ['operation', 'status'])

def extract_features(password):
    length = len(password)
    has_upper = 1 if any(c.isupper() for c in password) else 0
    has_lower = 1 if any(c.islower() for c in password) else 0
    has_digit = 1 if any(c.isdigit() for c in password) else 0
    has_special = 1 if any(not c.isalnum() for c in password) else 0
    
    # Character variety score (0-4)
    char_variety = has_upper + has_lower + has_digit + has_special
    
    # Penalize passwords that are only digits
    if password.isdigit():
        complexity_score = length * 0.5  # Heavy penalty for digit-only
    else:
        complexity_score = length + (char_variety * 3) + (has_special * 5)

    return np.array([length, char_variety, complexity_score]).reshape(1, -1)

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
        # Railway provides DATABASE_URL
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            conn = psycopg2.connect(database_url)
        else:
            conn = psycopg2.connect(
                host=os.environ.get("PGHOST", "db"),
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
        try:
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
                        prediction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user_id INTEGER REFERENCES users(id)
                    );
                """)
                
                # יצירת משתמש ברירת מחדל
                cur.execute("""
                    INSERT INTO users (username, password_hash) 
                    VALUES ('default_user', 'default_hash')
                    ON CONFLICT (username) DO NOTHING
                """)
                
            conn.commit()
        except Exception as e:
            print(f"Database setup error: {e}")
            conn.rollback()
        finally:
            conn.close()

create_table_if_not_exists()

# JWT Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'נדרש טוקן אימות'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'הטוקן פג תוקף'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'טוקן לא תקין'}), 401
        
        return f(current_user_id, *args, **kwargs)
    return decorated

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_token(user_id):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

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
        return generate_strong_password(12)
    
    max_attempts = 10
    for attempt in range(max_attempts):
        # בחירת סיסמה בסיסית אקראית
        base_password = random.choice(password_list).lower()
        
        # אסטרטגיות שונות לוריאציה
        strategies = [
            # הוספת מספרים ותווים מיוחדים
            lambda p: p.capitalize() + str(random.randint(10, 999)) + random.choice(['!', '@', '#', '$']),
            lambda p: p.upper()[:4] + p.lower()[4:] + str(random.randint(100, 999)) + '!',
            lambda p: random.choice(['My', 'The', 'New']) + p.capitalize() + str(random.randint(10, 99)) + '@',
            
            # שילוב מורכב
            lambda p: p[:3].capitalize() + str(random.randint(10, 99)) + p[3:].lower() + random.choice(['!@', '#$', '%&']),
            lambda p: p.capitalize() + random.choice(['123!', '456@', '789#', '2024$']),
        ]
        
        # בחירת אסטרטגיה אקראית ויישום
        strategy = random.choice(strategies)
        result = strategy(base_password)
        
        # וידוא שהתוצאה באורך מתאים
        if len(result) < 8:
            result += str(random.randint(10, 99)) + '!'
        
        # בדיקה שהסיסמה חזקה
        try:
            strength, _ = get_prediction_and_crack_time(result)
            if strength >= 2:  # רק סיסמאות חזקות
                return result
        except:
            continue
    
    # אם לא הצלחנו ליצור סיסמה חזקה, נחזיר סיסמה חזקה גנרית
    return generate_strong_password(12)


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
@limiter.limit("5 per minute")
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
            
            if user and verify_password(password, user[1]):
                token = generate_token(user[0])
                return jsonify({
                    "success": True, 
                    "message": "התחברת בהצלחה",
                    "token": token
                })
            else:
                return jsonify({"error": "שם משתמש או סיסמה שגויים"}), 401
    finally:
        conn.close()

@app.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({"error": "נדרש שם משתמש וסיסמה"}), 400
    
    # Password strength validation
    if len(password) < 8:
        return jsonify({"error": "הסיסמה חייבת להיות באורך 8 תווים לפחות"}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "שגיאת חיבור למסד נתונים"}), 500
    
    try:
        with conn.cursor() as cur:
            password_hash = hash_password(password)
            cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id", 
                       (username, password_hash))
            user_id = cur.fetchone()[0]
            conn.commit()
            
            token = generate_token(user_id)
            return jsonify({
                "success": True, 
                "message": "נרשמת בהצלחה",
                "token": token
            })
    except Exception as e:
        if "duplicate key" in str(e):
            return jsonify({"error": "שם המשתמש כבר קיים"}), 409
        return jsonify({"error": "שגיאה ביצירת המשתמש"}), 500
    finally:
        conn.close()

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user_id):
    # With JWT, logout is handled client-side by removing the token
    return jsonify({"success": True, "message": "התנתקת בהצלחה"})

@app.route('/score', methods=['POST'])
@token_required
def score_password(current_user_id):
    """Endpoint לבדיקה ושמירה ל-DB (פועל רק אם save_to_db=True)."""
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
                    password_hash = hashlib.sha256(password.encode()).hexdigest()
                    cur.execute("""
                        INSERT INTO password_scores (user_id, password_hash, plain_password, score)
                        VALUES (%s, %s, %s, %s);
                    """, (current_user_id, password_hash, password, prediction))
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
@token_required
def get_password_history(current_user_id):
    """
    Endpoint for retrieving all saved password scores from the database.
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database connection failed."}), 500
    
    results = []
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT plain_password, score, prediction_time
                FROM password_scores 
                WHERE user_id = %s
                ORDER BY prediction_time DESC
                LIMIT 10;
            """, (current_user_id,))
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


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for load balancer"""
    try:
        # Check database connection
        conn = get_db_connection()
        if conn:
            conn.close()
            db_status = "healthy"
        else:
            db_status = "unhealthy"
        
        # Check ML model
        model_status = "healthy" if MODEL else "unhealthy"
        
        status = "healthy" if db_status == "healthy" and model_status == "healthy" else "unhealthy"
        
        return jsonify({
            "status": status,
            "database": db_status,
            "ml_model": model_status,
            "timestamp": datetime.utcnow().isoformat()
        }), 200 if status == "healthy" else 503
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 503

def create_password_poem(password):
    """Create a safe poem for password memorization using only hints"""
    if not GEMINI_API_KEY:
        return "🎵 שיר הסיסמה שלי 🎵\nצריך מפתח Gemini API ליצירת שירים!"
    
    try:
        # Extract safe hints only - NO actual password
        hints = {
            "length": len(password),
            "has_numbers": "יש מספרים" if any(c.isdigit() for c in password) else "אין מספרים",
            "has_symbols": "יש סימנים מיוחדים" if any(not c.isalnum() for c in password) else "אין סימנים",
            "has_upper": "יש אותיות גדולות" if any(c.isupper() for c in password) else "אין אותיות גדולות",
            "has_lower": "יש אותיות קטנות" if any(c.islower() for c in password) else "אין אותיות קטנות",
            "starts_with": "מתחיל באות" if password[0].isalpha() else "מתחיל במספר" if password[0].isdigit() else "מתחיל בסימן",
            "complexity": "פשוטה" if len(set(password)) < len(password)//2 else "מורכבת"
        }
        
        prompt = f"""צור שיר קצר, חמוד וקליט בעברית לזכירת סיסמה עם המאפיינים הבאים:
        - אורך: {hints['length']} תווים
        - {hints['has_numbers']}
        - {hints['has_symbols']}
        - {hints['has_upper']}
        - {hints['has_lower']}
        - {hints['starts_with']}
        - רמת מורכבות: {hints['complexity']}
        
        השיר צריך להיות:
        - באורך 4-6 שורות
        - עם חרוזים
        - עם אמוג'י 🎵
        - לעזור לזכור את המאפיינים בלי לחשוף את הסיסמה האמיתית
        - מהנה וקליט
        
        התחל עם "🎵 שיר הסיסמה שלי 🎵"""
        
        # Use REST API directly
        import requests
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
        
        payload = {
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }]
        }
        
        response = requests.post(url, json=payload, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result and len(result['candidates']) > 0:
                poem_text = result['candidates'][0]['content']['parts'][0]['text']
                return poem_text
            else:
                return "🎵 שיר הסיסמה שלי 🎵\nלא הצלחתי ליצור שיר היום,\nאבל הסיסמה שלך עדיין חזקה! 💪"
        else:
            return "🎵 שיר הסיסמה שלי 🎵\nשגיאה ביצירת השיר,\nאבל הסיסמה שלך מוגנת! 🛡️"
        
    except Exception as e:
        return f"🎵 שיר הסיסמה שלי 🎵\nלא הצלחתי ליצור שיר היום,\nאבל הסיסמה שלך עדיין חזקה! 💪"


@app.route('/password-poem', methods=['POST'])
@token_required
def generate_password_poem(current_user_id):
    """Generate a safe poem for password memorization"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({"error": "נדרשת סיסמה ליצירת שיר"}), 400
    
    if len(password) < 4:
        return jsonify({"error": "הסיסמה קצרה מדי ליצירת שיר"}), 400
    
    try:
        poem = create_password_poem(password)
        
        return jsonify({
            "poem": poem,
            "message": "שיר נוצר בהצלחה! השיר לא חושף את הסיסמה שלך 🎵"
        })
        
    except Exception as e:
        return jsonify({"error": "שגיאה ביצירת השיר"}), 500

@app.route('/recommend', methods=['GET'])
@token_required
def recommend_password(current_user_id):
    """Endpoint המאמן מודל Markoc Chain על סיסמאות קודמות ומציע סיסמה חדשה."""

    # 1. שליפת סיסמאות חלשות שנשמרו מה-DB
    conn = get_db_connection()
    if not conn:
         return jsonify({"error": "DB connection failed for recommendation."}), 500

    # שליפת כל הסיסמאות שנשמרו ללמידה
    with conn.cursor() as cur:
        cur.execute("""
            SELECT plain_password FROM password_scores 
            WHERE user_id = %s
            ORDER BY prediction_time DESC LIMIT 50;
        """, (current_user_id,))
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


@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)