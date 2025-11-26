#!/bin/bash
# entrypoint.sh - Entrypoint for the API container

# 1. המתנה ל-PostgreSQL
echo "Waiting for postgres..."

while ! pg_isready -h db -p 5432 -U $POSTGRES_USER; do
  sleep 1
done

echo "PostgreSQL started. Running setup script."

# 2. הרצת פקודה חד-פעמית ליצירת הטבלה
# נשתמש בפקודה "flask shell" או בפקודה פשוטה כדי להריץ את הלוגיקה מ-app.py
# (נצטרך לשנות את אופן יצירת הטבלה ב-app.py, אבל בינתיים נשתמש בפקודה הזו כדוגמה)
python -c 'from app import create_table_if_not_exists; create_table_if_not_exists()'

echo "Database table ensured. Starting Gunicorn."

# 3. הרצת Gunicorn (השרת הראשי)
exec gunicorn --bind 0.0.0.0:8000 app:app